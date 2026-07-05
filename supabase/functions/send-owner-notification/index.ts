// @ts-nocheck
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-internal-webhook-secret',
}

serve(async (req) => {
  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // 1. Parse request payload
    const body = await req.json()
    const { type, order_id, seller_id } = body
    if (!type || (!order_id && !seller_id)) {
      return new Response(JSON.stringify({ error: 'Missing type, order_id or seller_id in request body' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // 2. Initialize Supabase Admin Client
    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? ''
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    const supabase = createClient(supabaseUrl, supabaseServiceKey)

    // Retrieve Resend Secrets early
    const resendApiKey = Deno.env.get('RESEND_API_KEY')
    const fromEmail = Deno.env.get('RESEND_FROM_EMAIL')
    const toEmail = Deno.env.get('RESEND_TO_EMAIL')

    if (!resendApiKey || !fromEmail) {
      console.error("Missing Resend secrets configuration in Supabase project")
      return new Response(JSON.stringify({ error: 'Server configuration error' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // 3. Handle seller application approved/rejected emails (admin triggered)
    if (type === 'seller_approved' || type === 'seller_rejected') {
      const authHeader = req.headers.get('Authorization')
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response(JSON.stringify({ error: 'Unauthorized: Missing user token' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      const token = authHeader.substring(7)

      // Verify JWT and get caller user details
      const { data: { user: callerUser }, error: callerError } = await supabase.auth.getUser(token)
      if (callerError || !callerUser) {
        console.error("Failed to verify caller JWT:", callerError)
        return new Response(JSON.stringify({ error: 'Unauthorized: Invalid user session' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      // Check if caller is admin
      const { data: callerProfile, error: callerProfileError } = await supabase
        .from('profiles')
        .select('role')
        .eq('id', callerUser.id)
        .single()
      
      if (callerProfileError || !callerProfile || callerProfile.role !== 'admin') {
        console.error("Forbidden access: caller is not an admin", callerProfileError)
        return new Response(JSON.stringify({ error: 'Forbidden: Admin role required' }), {
          status: 403,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      // Fetch seller profile details
      const { data: sellerProfile, error: sellerProfileError } = await supabase
        .from('profiles')
        .select('name, shop_name')
        .eq('id', seller_id)
        .single()

      if (sellerProfileError || !sellerProfile) {
        console.error(`Seller profile not found for ID: ${seller_id}`, sellerProfileError)
        return new Response(JSON.stringify({ error: 'Seller profile not found' }), {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      // Fetch seller auth user details (for email)
      const { data: authUser, error: authUserError } = await supabase.auth.admin.getUserById(seller_id)
      if (authUserError || !authUser?.user) {
        console.error(`Auth user details not found for seller ID: ${seller_id}`, authUserError)
        return new Response(JSON.stringify({ error: 'Seller email not found in auth' }), {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      const sellerEmail = authUser.user.email
      if (!sellerEmail) {
        return new Response(JSON.stringify({ error: 'Seller email is blank' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      let emailSubject = ''
      let emailHtml = ''

      if (type === 'seller_approved') {
        emailSubject = `[Storify] Your Seller Application has been Approved!`
        emailHtml = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #4A90E2; border-bottom: 2px solid #4A90E2; padding-bottom: 10px;">Application Approved!</h2>
            <p style="color: #333; font-size: 14px; line-height: 1.6;">
              Hello <strong>${sellerProfile.name || 'Seller'}</strong>,
            </p>
            <p style="color: #333; font-size: 14px; line-height: 1.6;">
              Congratulations! Your application to become a vendor on Storify has been <strong>approved</strong>.
            </p>
            <div style="background-color: #f0f8ff; padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 4px solid #4A90E2;">
              <table style="width: 100%; border-collapse: collapse;">
                <tr>
                  <td style="padding: 4px 0; font-weight: bold; color: #555; width: 35%;">Shop Name:</td>
                  <td style="padding: 4px 0; color: #333; font-weight: bold;">${sellerProfile.shop_name}</td>
                </tr>
                <tr>
                  <td style="padding: 4px 0; font-weight: bold; color: #555;">Status:</td>
                  <td style="padding: 4px 0; color: #2e7d32; font-weight: bold;">Approved</td>
                </tr>
              </table>
            </div>
            <p style="color: #333; font-size: 14px; line-height: 1.6;">
              You can now access your dedicated seller portal to upload products, view orders, and manage settings.
            </p>
            <div style="text-align: center; margin: 25px 0;">
              <a href="https://shop.storify.services/seller.html" style="background-color: #4A90E2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block; box-shadow: 0 4px 10px rgba(74, 144, 226, 0.3);">Go to Seller Portal</a>
            </div>
            <div style="margin-top: 30px; text-align: center; font-size: 11px; color: #888888; border-top: 1px solid #e0e0e0; padding-top: 15px;">
              This email was generated automatically by the Storify Shop platform.
            </div>
          </div>
        `
      } else {
        emailSubject = `[Storify] Update on your Seller Application`
        emailHtml = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 10px;">Application Reviewed</h2>
            <p style="color: #333; font-size: 14px; line-height: 1.6;">
              Hello <strong>${sellerProfile.name || 'Seller'}</strong>,
            </p>
            <p style="color: #333; font-size: 14px; line-height: 1.6;">
              Thank you for applying to become a seller on Storify. After reviewing the details provided for your shop (<strong>${sellerProfile.shop_name}</strong>), we regret to inform you that we are unable to approve your application at this time.
            </p>
            <p style="color: #333; font-size: 14px; line-height: 1.6;">
              If you have any questions or would like to submit additional information, please contact our support team.
            </p>
            <div style="margin-top: 30px; text-align: center; font-size: 11px; color: #888888; border-top: 1px solid #e0e0e0; padding-top: 15px;">
              This email was generated automatically by the Storify Shop platform.
            </div>
          </div>
        `
      }

      // Send email via Resend
      const resendResponse = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${resendApiKey}`
        },
        body: JSON.stringify({
          from: fromEmail,
          to: sellerEmail,
          subject: emailSubject,
          html: emailHtml
        })
      })

      if (!resendResponse.ok) {
        const errorText = await resendResponse.text()
        console.error(`[Error] Resend API invocation failed with status ${resendResponse.status}: ${errorText}`)
        throw new Error(`Resend API failed: ${errorText}`)
      }

      const resendData = await resendResponse.json()
      return new Response(JSON.stringify({ success: true, message: 'Seller email sent successfully', id: resendData?.id }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // 4. Continue with existing order logic
    // Fetch Order Data (including buyer_id to verify ownership)
    const { data: order, error: orderError } = await supabase
      .from('orders')
      .select('*, profiles(name, phone)')
      .eq('id', order_id)
      .single()

    if (orderError || !order) {
      console.error(`Order not found for ID: ${order_id}`, orderError)
      return new Response(JSON.stringify({ error: 'Order not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Fetch buyer email from auth schema using Admin API
    let buyerEmail = 'N/A'
    if (order.buyer_id) {
      const { data: authUser, error: authUserError } = await supabase.auth.admin.getUserById(order.buyer_id)
      if (!authUserError && authUser?.user) {
        buyerEmail = authUser.user.email || 'N/A'
      } else {
        console.warn(`Failed to fetch auth user details for buyer_id: ${order.buyer_id}`, authUserError)
      }
    }

    // Resolve details entered during checkout (or fallback to profile defaults)
    const displayBuyerName = order.shipping_name || order.profiles?.name || 'Guest Buyer'
    const displayBuyerPhone = order.shipping_phone || order.profiles?.phone || 'N/A'
    const displayBuyerEmail = order.shipping_email || buyerEmail

    // 5. Validate request based on notification type
    if (type === 'new_order') {
      const authHeader = req.headers.get('Authorization')
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response(JSON.stringify({ error: 'Unauthorized: Missing user session token' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      const token = authHeader.substring(7)
      
      // Verify JWT and get user
      const { data: { user }, error: userError } = await supabase.auth.getUser(token)
      if (userError || !user) {
        console.error("Failed to verify user JWT token:", userError)
        return new Response(JSON.stringify({ error: 'Unauthorized: Invalid user session' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      // Verify that this order belongs to the authenticated user
      if (order.buyer_id !== user.id) {
        console.warn(`Access Denied: User ${user.id} tried to trigger new_order notification for order owned by ${order.buyer_id}`)
        return new Response(JSON.stringify({ error: 'Forbidden: You do not own this order' }), {
          status: 403,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
    } else if (type === 'payment_received') {
      const internalSecret = Deno.env.get('INTERNAL_WEBHOOK_SECRET')
      const receivedSecret = req.headers.get('x-internal-webhook-secret')

      if (!internalSecret || receivedSecret !== internalSecret) {
        console.warn("Unauthorized attempt to trigger payment received email via internal secret mismatch")
        return new Response(JSON.stringify({ error: 'Unauthorized: Missing or invalid secret key' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
    }



    // 5. Retrieve Resend Secrets
    const resendApiKey = Deno.env.get('RESEND_API_KEY')
    const fromEmail = Deno.env.get('RESEND_FROM_EMAIL')
    const toEmail = Deno.env.get('RESEND_TO_EMAIL')

    if (!resendApiKey || !fromEmail || !toEmail) {
      console.error("Missing Resend secrets configuration in Supabase project")
      return new Response(JSON.stringify({ error: 'Server configuration error' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // 6. Fetch Order Items (for both email types so we always show order details)
    const { data: items, error: itemsError } = await supabase
      .from('order_items')
      .select('quantity, price_at_purchase, product_id, seller_id')
      .eq('order_id', order_id)

    if (itemsError || !items || items.length === 0) {
      console.error(`No order items found for Order ID: ${order_id}`, itemsError)
      return new Response(JSON.stringify({ error: 'Order items not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // Fetch Product Names and Seller Shop Names in bulk
    const productIds = items.map(i => i.product_id).filter(Boolean)
    const sellerIds = items.map(i => i.seller_id).filter(Boolean)

    const { data: products } = await supabase
      .from('products')
      .select('id, name')
      .in('id', productIds)

    const { data: sellers } = await supabase
      .from('profiles')
      .select('id, shop_name, name, phone')
      .in('id', sellerIds)

    const productMap = Object.fromEntries(products?.map(p => [p.id, p.name]) || [])

    // Resolve detailed contact info for each seller from Auth/Profiles schema
    const sellerDetailsMap = {}
    if (sellers && sellers.length > 0) {
      for (const seller of sellers) {
        let sellerEmail = 'N/A'
        const { data: authUser } = await supabase.auth.admin.getUserById(seller.id)
        if (authUser?.user) {
          sellerEmail = authUser.user.email || 'N/A'
        }
        sellerDetailsMap[seller.id] = {
          shopName: seller.shop_name || 'N/A',
          ownerName: seller.name || 'N/A',
          phone: seller.phone || 'N/A',
          email: sellerEmail
        }
      }
    }

    // Formulate HTML items table
    let itemsRows = ''
    let recalculatedSubtotal = 0

    for (const item of items) {
      const name = productMap[item.product_id] || `Product ID #${item.product_id}`
      
      // Load detailed seller fields
      const sellerInfo = sellerDetailsMap[item.seller_id] || {
        shopName: 'Admin Seeded / Store Owner',
        ownerName: 'N/A',
        phone: 'N/A',
        email: 'N/A'
      }

      const itemTotal = Number(item.price_at_purchase) * Number(item.quantity)
      recalculatedSubtotal += itemTotal

      itemsRows += `
        <tr style="border-bottom: 1px solid #eeeeee;">
          <td style="padding: 10px 0; font-weight: bold; color: #333333; vertical-align: top;">${name}</td>
          <td style="padding: 10px 0; text-align: center; color: #666666; vertical-align: top;">${item.quantity}</td>
          <td style="padding: 10px 0; text-align: right; color: #666666; vertical-align: top;">RS ${Number(item.price_at_purchase).toLocaleString()}</td>
          <td style="padding: 10px 0; text-align: right; font-weight: bold; color: #1a1a2e; vertical-align: top;">RS ${itemTotal.toLocaleString()}</td>
          <td style="padding: 10px 0; text-align: right; color: #555555; font-size: 11px; line-height: 1.4; vertical-align: top;">
            <strong style="color: #0066cc;">${sellerInfo.shopName}</strong><br/>
            <span style="color: #666;">
              Owner: ${sellerInfo.ownerName}<br/>
              Phone: ${sellerInfo.phone}<br/>
              Email: ${sellerInfo.email}
            </span>
          </td>
        </tr>
      `
    }

    const shipping = 250
    const orderTotal = recalculatedSubtotal + shipping

    let emailSubject = ''
    let emailHtml = ''

    if (type === 'new_order') {
      emailSubject = `[Storify] New Order Placed - ${order.order_ref}`
      emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 10px;">New Order Placed Notification</h2>
          
          <div style="background-color: #f9f9f9; padding: 15px; border-radius: 6px; margin: 15px 0;">
            <h3 style="margin-top: 0; color: #333;">Order Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555;">Order Reference:</td>
                <td style="padding: 4px 0; color: #1a1a2e; font-weight: bold;">${order.order_ref}</td>
              </tr>
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555;">Total Amount:</td>
                <td style="padding: 4px 0; color: #1a1a2e; font-weight: bold;">RS ${orderTotal.toLocaleString()} <span style="font-size: 11px; font-weight: normal; color: #666;">(Subtotal + RS 250 Shipping)</span></td>
              </tr>
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555;">Placed At:</td>
                <td style="padding: 4px 0; color: #555;">${new Date(order.created_at).toLocaleString('en-US', { timeZone: 'UTC' })} UTC</td>
              </tr>
            </table>
          </div>

          <div style="margin: 15px 0;">
            <h3 style="color: #333;">Buyer Information</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555; width: 30%;">Name:</td>
                <td style="padding: 4px 0; color: #333;">${displayBuyerName}</td>
              </tr>
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555;">Email:</td>
                <td style="padding: 4px 0; color: #333;">${displayBuyerEmail}</td>
              </tr>
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555;">Phone:</td>
                <td style="padding: 4px 0; color: #333;">${displayBuyerPhone}</td>
              </tr>
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555; vertical-align: top;">Shipping Address:</td>
                <td style="padding: 4px 0; color: #333;">${order.shipping_address}</td>
              </tr>
            </table>
          </div>

          <div style="margin: 20px 0;">
            <h3 style="color: #333; border-bottom: 1px solid #ddd; padding-bottom: 6px;">Order Items</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <thead>
                <tr style="border-bottom: 2px solid #dddddd; text-align: left; font-size: 12px; color: #666666;">
                  <th style="padding: 8px 0; text-align: left;">Product</th>
                  <th style="padding: 8px 0; text-align: center; width: 10%;">Qty</th>
                  <th style="padding: 8px 0; text-align: right; width: 20%;">Price</th>
                  <th style="padding: 8px 0; text-align: right; width: 20%;">Total</th>
                  <th style="padding: 8px 0; text-align: right; width: 25%;">Seller</th>
                </tr>
              </thead>
              <tbody>
                ${itemsRows}
              </tbody>
            </table>
          </div>

          <div style="margin-top: 30px; text-align: center; font-size: 11px; color: #888888; border-top: 1px solid #e0e0e0; padding-top: 15px;">
            This email was generated automatically by the Storify Shop platform.
          </div>
        </div>
      `
    } else if (type === 'payment_received') {
      emailSubject = `[Storify] Payment Confirmed - ${order.order_ref}`
      emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #2e7d32; border-bottom: 2px solid #2e7d32; padding-bottom: 10px;">Payment Confirmation Received</h2>
          
          <p style="color: #333; font-size: 14px; line-height: 1.6;">
            Excellent news! Payment for order reference <strong>${order.order_ref}</strong> has been secured via Safepay escrow.
          </p>

          <div style="background-color: #f1f8e9; padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 4px solid #2e7d32;">
            <h3 style="margin-top: 0; color: #2e7d32;">Payment Summary</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 6px 0; font-weight: bold; color: #555; width: 40%;">Order Reference:</td>
                <td style="padding: 6px 0; color: #1a1a2e; font-weight: bold;">${order.order_ref}</td>
              </tr>
              <tr>
                <td style="padding: 6px 0; font-weight: bold; color: #555;">Payment Method:</td>
                <td style="padding: 6px 0; color: #333; text-transform: uppercase;">${order.payment_method || 'N/A'}</td>
              </tr>
              <tr>
                <td style="padding: 6px 0; font-weight: bold; color: #555;">Safepay Ref ID:</td>
                <td style="padding: 6px 0; color: #333; font-family: monospace;">${order.payment_reference || 'N/A'}</td>
              </tr>
              <tr>
                <td style="padding: 6px 0; font-weight: bold; color: #555;">Total Settled:</td>
                <td style="padding: 6px 0; color: #2e7d32; font-weight: bold; font-size: 16px;">RS ${Number(order.total_amount).toLocaleString()}</td>
              </tr>
              <tr>
                <td style="padding: 6px 0; font-weight: bold; color: #555;">Confirmation Time:</td>
                <td style="padding: 6px 0; color: #555;">${new Date().toLocaleString('en-US', { timeZone: 'UTC' })} UTC</td>
              </tr>
            </table>
          </div>

          <div style="margin: 15px 0;">
            <h3 style="color: #333;">Buyer Information</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555; width: 30%;">Name:</td>
                <td style="padding: 4px 0; color: #333;">${displayBuyerName}</td>
              </tr>
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555;">Email:</td>
                <td style="padding: 4px 0; color: #333;">${displayBuyerEmail}</td>
              </tr>
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555;">Phone:</td>
                <td style="padding: 4px 0; color: #333;">${displayBuyerPhone}</td>
              </tr>
              <tr>
                <td style="padding: 4px 0; font-weight: bold; color: #555; vertical-align: top;">Shipping Address:</td>
                <td style="padding: 4px 0; color: #333;">${order.shipping_address}</td>
              </tr>
            </table>
          </div>

          <div style="margin: 20px 0;">
            <h3 style="color: #333; border-bottom: 1px solid #ddd; padding-bottom: 6px;">Order Items</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <thead>
                <tr style="border-bottom: 2px solid #dddddd; text-align: left; font-size: 12px; color: #666666;">
                  <th style="padding: 8px 0; text-align: left;">Product</th>
                  <th style="padding: 8px 0; text-align: center; width: 10%;">Qty</th>
                  <th style="padding: 8px 0; text-align: right; width: 20%;">Price</th>
                  <th style="padding: 8px 0; text-align: right; width: 20%;">Total</th>
                  <th style="padding: 8px 0; text-align: right; width: 25%;">Seller</th>
                </tr>
              </thead>
              <tbody>
                ${itemsRows}
              </tbody>
            </table>
          </div>

          <p style="color: #666; font-size: 12px; margin-top: 20px;">
            The order status has been updated to <strong>Paid (Escrow)</strong> in the database, and individual sellers have been cleared to ship their items.
          </p>

          <div style="margin-top: 30px; text-align: center; font-size: 11px; color: #888888; border-top: 1px solid #e0e0e0; padding-top: 15px;">
            This email was generated automatically by the Storify Shop platform.
          </div>
        </div>
      `
    } else {
      return new Response(JSON.stringify({ error: `Invalid notification type: ${type}` }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // 7. Invoke Resend API
    const resendResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${resendApiKey}`
      },
      body: JSON.stringify({
        from: fromEmail,
        to: toEmail,
        subject: emailSubject,
        html: emailHtml
      })
    })

    if (!resendResponse.ok) {
      const errorText = await resendResponse.text()
      // CRITICAL: Log detailed Resend errors for visibility in dashboard
      console.error(`[Error] Resend API invocation failed with status ${resendResponse.status}: ${errorText}`)
      throw new Error(`Resend API failed: ${errorText}`)
    }

    const resendData = await resendResponse.json()
    return new Response(JSON.stringify({ success: true, message: 'Email sent successfully', id: resendData?.id }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err)
    console.error(`[Fatal Error] send-owner-notification failure: ${errorMessage}`)
    return new Response(JSON.stringify({ error: errorMessage }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
