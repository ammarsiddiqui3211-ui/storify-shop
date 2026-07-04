// @ts-nocheck
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Helper function to verify Safepay signature using Web Crypto API
async function verifySafepaySignature(
  rawBody: string,
  signature: string,
  timestamp: string,
  secret: string
): Promise<boolean> {
  try {
    const data = timestamp + '.' + rawBody
    const encoder = new TextEncoder()
    const keyData = encoder.encode(secret)
    const messageData = encoder.encode(data)

    const key = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    )

    // Convert hex signature string to bytes
    const matches = signature.match(/.{1,2}/g)
    if (!matches) return false
    const signatureBytes = new Uint8Array(
      matches.map((byte) => parseInt(byte, 16))
    )

    return await crypto.subtle.verify(
      "HMAC",
      key,
      signatureBytes,
      messageData
    )
  } catch (err) {
    console.error('Signature verification exception:', err)
    return false
  }
}

serve(async (req) => {
  // Handle CORS
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const signature = req.headers.get('x-sfpy-signature')
    const timestamp = req.headers.get('x-sfpy-timestamp')
    const secret = Deno.env.get('SAFEPAY_WEBHOOK_SECRET') || ''

    const rawBody = await req.text()
    
    // Verify signature
    if (!signature || !timestamp) {
      return new Response(JSON.stringify({ error: 'Missing signature headers' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (secret) {
      const isValid = await verifySafepaySignature(rawBody, signature, timestamp, secret)
      if (!isValid) {
        return new Response(JSON.stringify({ error: 'Invalid signature' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
    } else {
      console.warn('SAFEPAY_WEBHOOK_SECRET is not configured. Skipping signature check.')
    }

    const payload = JSON.parse(rawBody)
    const event = payload?.event
    const tracker = payload?.data?.tracker
    const reference = payload?.data?.reference
    const method = payload?.data?.payment?.channel || 'card'

    if (event !== 'payment.succeeded') {
      return new Response(JSON.stringify({ message: 'Ignored non-success event' }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (!tracker || !reference) {
      return new Response(JSON.stringify({ error: 'Missing tracker or reference' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Initialize Supabase Client with service role key to execute confirm_payment_via_webhook
    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? ''
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    const supabase = createClient(supabaseUrl, supabaseServiceKey)

    // 1. Look up the order by tracker token
    const { data: order, error: orderError } = await supabase
      .from('orders')
      .select('order_ref')
      .eq('tracker_token', tracker)
      .single()

    if (orderError || !order) {
      console.error('Order look up failed for tracker token:', tracker, orderError)
      return new Response(JSON.stringify({ error: 'Order not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // 2. Call confirm_payment_via_webhook securely as admin/service_role
    const { error: rpcError } = await supabase.rpc('confirm_payment_via_webhook', {
      p_order_ref: order.order_ref,
      p_payment_method: method,
      p_payment_reference: reference,
    })

    if (rpcError) {
      console.error('Failed to confirm payment via RPC:', rpcError)
      return new Response(JSON.stringify({ error: 'Failed to settle order payment' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    return new Response(JSON.stringify({ status: 'success', message: 'Order paid successfully' }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (err) {
    console.error('Webhook error:', err)
    const errorMessage = err instanceof Error ? err.message : String(err)
    return new Response(JSON.stringify({ error: errorMessage }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
