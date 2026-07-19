// @ts-nocheck
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  // Handle CORS
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { order_id } = await req.json()
    if (!order_id) {
      return new Response(JSON.stringify({ error: 'order_id is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Initialize Supabase Client with service role key to bypass RLS for verification
    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? ''
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    const supabase = createClient(supabaseUrl, supabaseServiceKey)

    // 1. Fetch order and its order items
    const { data: orderItems, error: itemsError } = await supabase
      .from('order_items')
      .select('price_at_purchase, quantity, seller_id, shipping_fee_at_purchase')
      .eq('order_id', order_id)

    if (itemsError || !orderItems || orderItems.length === 0) {
      return new Response(JSON.stringify({ error: 'Order items not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // 2. Recalculate order total from actual line items (per-seller shipping max)
    let subtotal = 0
    const sellerShippingMap = new Map()
    for (const item of orderItems) {
      subtotal += Number(item.price_at_purchase) * Number(item.quantity)
      
      const sId = item.seller_id || 'unknown'
      const fee = Number(item.shipping_fee_at_purchase || 0)
      if (!sellerShippingMap.has(sId) || fee > sellerShippingMap.get(sId)) {
        sellerShippingMap.set(sId, fee)
      }
    }

    let shipping = 0
    for (const fee of sellerShippingMap.values()) {
      shipping += fee
    }
    const totalAmount = subtotal + shipping

    // 3. Update orders table with the locked recalculated total amount
    const { error: updateError } = await supabase
      .from('orders')
      .update({ total_amount: totalAmount })
      .eq('id', order_id)

    if (updateError) {
      return new Response(JSON.stringify({ error: 'Failed to update order total' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // 4. Initialize Safepay Sandbox Checkout session
    // For sandbox, use public key (client). Fallback to standard sandbox credentials if not set in environment.
    const safepayClientKey = Deno.env.get('SAFEPAY_PUBLIC_KEY') || 'sec_4be8-c923-1d48c081e7d2'
    
    const safepayResponse = await fetch('https://sandbox.api.getsafepay.com/order/v1/init', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client: safepayClientKey,
        amount: totalAmount,
        currency: 'PKR',
        environment: 'sandbox',
      }),
    })

    if (!safepayResponse.ok) {
      const errorText = await safepayResponse.text()
      console.error('Safepay error response:', errorText)
      throw new Error('Safepay order initialization failed')
    }

    const safepayData = await safepayResponse.json()
    const trackerToken = safepayData?.data?.token

    if (!trackerToken) {
      throw new Error('No tracker token returned from Safepay')
    }

    // Save the tracker token to the order record
    const { error: trackerUpdateError } = await supabase
      .from('orders')
      .update({ tracker_token: trackerToken })
      .eq('id', order_id)

    if (trackerUpdateError) {
      console.error('Failed to save tracker token:', trackerUpdateError)
      throw new Error('Failed to save tracker token to order record')
    }

    return new Response(JSON.stringify({ token: trackerToken, amount: totalAmount }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err)
    return new Response(JSON.stringify({ error: errorMessage }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
