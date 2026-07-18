-- SQL Schema for Storify Store Database (Supabase PostgreSQL Edition)
-- Copy and run this script inside the Supabase SQL Editor.

-- Enable UUID extension if not enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create App Settings table for persistent configuration (e.g. dev mode)
CREATE TABLE IF NOT EXISTS public.app_settings (
  key text PRIMARY KEY,
  value text NOT NULL
);

-- Enable RLS on app_settings
ALTER TABLE public.app_settings ENABLE ROW LEVEL SECURITY;

-- Allow only admins to read or write settings
CREATE POLICY "Allow read access to app_settings for admin only" ON public.app_settings
  FOR SELECT TO authenticated USING (public.is_admin(auth.uid()));

CREATE POLICY "Allow write access to app_settings for admin only" ON public.app_settings
  FOR ALL TO authenticated USING (public.is_admin(auth.uid()));

-- Insert default dev_mode as false
INSERT INTO public.app_settings (key, value)
VALUES ('dev_mode', 'false')
ON CONFLICT (key) DO NOTHING;

-- Helper to check if dev mode is active
CREATE OR REPLACE FUNCTION public.is_dev_mode()
RETURNS boolean AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.app_settings
    WHERE key = 'dev_mode' AND value = 'true'
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ----------------------------------------------------
-- 1. UTILITY FUNCTIONS & SCHEMAS
-- ----------------------------------------------------

-- Helper function to check if user is admin (prevents RLS recursion)
CREATE OR REPLACE FUNCTION public.is_admin(p_user_id uuid)
RETURNS boolean AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = p_user_id AND role = 'admin'
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ----------------------------------------------------
-- 2. PROFILES TABLE & TRIGGERS
-- ----------------------------------------------------

CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  role text NOT NULL DEFAULT 'buyer' CHECK (role IN ('buyer', 'seller', 'admin')),
  seller_status text NOT NULL DEFAULT 'none' CHECK (seller_status IN ('none', 'pending', 'approved', 'rejected', 'suspended')),
  shop_name text,
  bank_account_details text,
  seller_score numeric NOT NULL DEFAULT 100,
  name text,
  phone text,
  address text,
  city text,
  zip text,
  updated_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Allow users to select their own profile or admin" ON public.profiles
  FOR SELECT TO authenticated USING (auth.uid() = id OR public.is_admin(auth.uid()));

CREATE POLICY "Allow users to update their own profile or admin" ON public.profiles
  FOR UPDATE TO authenticated USING (auth.uid() = id OR public.is_admin(auth.uid()))
  WITH CHECK (auth.uid() = id OR public.is_admin(auth.uid()));

-- Trigger to sync auth.users with public.profiles on insert
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, role, seller_status, seller_score, name, phone, address, city, zip)
  VALUES (
    NEW.id,
    'buyer',
    'none',
    100,
    COALESCE(NEW.raw_user_meta_data->>'name', ''),
    COALESCE(NEW.raw_user_meta_data->>'phone', ''),
    COALESCE(NEW.raw_user_meta_data->>'address', ''),
    COALESCE(NEW.raw_user_meta_data->>'city', ''),
    COALESCE(NEW.raw_user_meta_data->>'zip', '')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Trigger to prevent non-admins from updating role, seller_status, and seller_score
CREATE OR REPLACE FUNCTION public.enforce_profile_update_restrictions()
RETURNS TRIGGER AS $$
BEGIN
  -- Prevent role modification to admin unless current auth user is admin
  IF NEW.role = 'admin' AND OLD.role IS DISTINCT FROM 'admin' THEN
    IF NOT public.is_admin(auth.uid()) THEN
      RAISE EXCEPTION 'Only admins can grant admin role';
    END IF;
  END IF;

  -- Prevent seller status approval unless admin
  IF NEW.seller_status = 'approved' AND OLD.seller_status IS DISTINCT FROM 'approved' THEN
    IF NOT public.is_admin(auth.uid()) THEN
      RAISE EXCEPTION 'Only admins can approve sellers';
    END IF;
  END IF;

  -- Prevent seller status suspension unless admin
  IF NEW.seller_status = 'suspended' AND OLD.seller_status IS DISTINCT FROM 'suspended' THEN
    IF NOT public.is_admin(auth.uid()) THEN
      RAISE EXCEPTION 'Only admins can suspend sellers';
    END IF;
  END IF;

  -- Prevent score updates unless admin
  IF NEW.seller_score IS DISTINCT FROM OLD.seller_score THEN
    IF NOT public.is_admin(auth.uid()) THEN
      RAISE EXCEPTION 'Only admins can modify seller score';
    END IF;
  END IF;

  -- Allow transition to seller if they submit registration details
  IF NEW.role = 'seller' AND OLD.role = 'buyer' THEN
    IF NEW.seller_status NOT IN ('pending', 'approved') THEN
      RAISE EXCEPTION 'Invalid seller status transition';
    END IF;
    IF NEW.shop_name IS NULL OR NEW.bank_account_details IS NULL THEN
      RAISE EXCEPTION 'Shop name and bank details are required to become a seller';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_profile_updated_restricted
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.enforce_profile_update_restrictions();

-- ----------------------------------------------------
-- 3. PRODUCTS TABLE, VIEW, & TRIGGERS
-- ----------------------------------------------------

CREATE TABLE IF NOT EXISTS public.products (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  name text NOT NULL,
  description text NOT NULL,
  price numeric NOT NULL,
  original_price numeric,
  category text NOT NULL,
  category_key text NOT NULL,
  images text[] NOT NULL,
  colors text[],
  sizes text[],
  specs jsonb DEFAULT '{}'::jsonb NOT NULL,
  seller_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  verified_badge boolean NOT NULL DEFAULT false,
  stock_status text NOT NULL DEFAULT 'available' CHECK (stock_status IN ('available', 'sold_out')),
  gradient text,
  featured boolean DEFAULT false,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY "Allow select on products for owner or admin" ON public.products
  FOR SELECT TO authenticated USING (auth.uid() = seller_id OR public.is_admin(auth.uid()));

CREATE POLICY "Allow insert on products for approved sellers" ON public.products
  FOR INSERT TO authenticated
  WITH CHECK (
    auth.uid() = seller_id AND
    (SELECT role FROM public.profiles WHERE id = auth.uid()) = 'seller' AND
    (SELECT seller_status FROM public.profiles WHERE id = auth.uid()) = 'approved'
  );

CREATE POLICY "Allow update on products for owner or admin" ON public.products
  FOR UPDATE TO authenticated
  USING (auth.uid() = seller_id OR public.is_admin(auth.uid()))
  WITH CHECK (auth.uid() = seller_id OR public.is_admin(auth.uid()));

CREATE POLICY "Allow delete on products for owner or admin" ON public.products
  FOR DELETE TO authenticated
  USING (auth.uid() = seller_id OR public.is_admin(auth.uid()));

-- Trigger to restrict verified_badge modification to admins
CREATE OR REPLACE FUNCTION public.enforce_product_update_restrictions()
RETURNS TRIGGER AS $$
BEGIN
  IF (NEW.verified_badge IS DISTINCT FROM OLD.verified_badge) THEN
    IF NOT public.is_admin(auth.uid()) THEN
      RAISE EXCEPTION 'Only admins can modify verified_badge';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_product_updated_restricted
  BEFORE UPDATE ON public.products
  FOR EACH ROW EXECUTE FUNCTION public.enforce_product_update_restrictions();

-- VIEW to hide seller details from buyers
CREATE OR REPLACE VIEW public.public_products AS
  SELECT
    id,
    name,
    description,
    price,
    original_price,
    category,
    category_key,
    images,
    colors,
    sizes,
    specs,
    verified_badge,
    stock_status,
    gradient,
    featured,
    created_at
  FROM public.products;

-- Grant public read access to the view
GRANT SELECT ON public.public_products TO anon, authenticated;

-- ----------------------------------------------------
-- 4. ORDERS TABLE & TRIGGERS
-- ----------------------------------------------------

CREATE TABLE IF NOT EXISTS public.orders (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  order_ref text NOT NULL UNIQUE,
  buyer_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'pending_payment' CHECK (status IN ('pending_payment', 'paid_escrow', 'shipped', 'delivered', 'return_window', 'completed', 'disputed', 'refunded')),
  delivered_at timestamp with time zone,
  shipping_address text NOT NULL,
  payment_method text, -- 'card' | 'jazzcash' | 'easypaisa'
  payment_reference text UNIQUE, -- Gateway transaction ID (UNIQUE)
  tracker_token text UNIQUE, -- Safepay tracker token
  total_amount numeric NOT NULL,
  shipping_name text,
  shipping_phone text,
  shipping_email text,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY "Allow select on orders for buyer or admin" ON public.orders
  FOR SELECT TO authenticated USING (auth.uid() = buyer_id OR public.is_admin(auth.uid()));

CREATE POLICY "Allow insert on orders for buyer" ON public.orders
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = buyer_id);

CREATE POLICY "Allow update on orders for admin only" ON public.orders
  FOR UPDATE TO authenticated USING (public.is_admin(auth.uid()));

-- Trigger to force orders status to 'pending_payment' on insert
CREATE OR REPLACE FUNCTION public.enforce_order_insert_defaults()
RETURNS TRIGGER AS $$
BEGIN
  NEW.status := 'pending_payment';
  NEW.payment_reference := NULL;
  NEW.payment_method := NULL;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_order_inserted_defaults
  BEFORE INSERT ON public.orders
  FOR EACH ROW EXECUTE FUNCTION public.enforce_order_insert_defaults();

-- ----------------------------------------------------
-- 5. ORDER_ITEMS TABLE & TRIGGERS
-- ----------------------------------------------------

CREATE TABLE IF NOT EXISTS public.order_items (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  order_id uuid REFERENCES public.orders(id) ON DELETE CASCADE NOT NULL,
  product_id bigint REFERENCES public.products(id) ON DELETE SET NULL,
  seller_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  quantity integer NOT NULL CHECK (quantity > 0),
  price_at_purchase numeric NOT NULL,
  item_status text NOT NULL DEFAULT 'pending_payment' CHECK (item_status IN ('pending_payment', 'paid_escrow', 'shipped', 'delivered', 'return_window', 'completed', 'disputed', 'refunded')),
  payout_released boolean NOT NULL DEFAULT false,
  delivered_at timestamp with time zone, -- per-item return-window tracking
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS
ALTER TABLE public.order_items ENABLE ROW LEVEL SECURITY;

-- Helper to check if a user is the buyer of a specific order (SECURITY DEFINER to bypass cross-table RLS issues)
CREATE OR REPLACE FUNCTION public.is_order_buyer(p_order_id uuid, p_user_id uuid)
RETURNS boolean AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.orders
    WHERE id = p_order_id AND buyer_id = p_user_id
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Policies
CREATE POLICY "Allow select on order_items for seller, buyer, or admin" ON public.order_items
  FOR SELECT TO authenticated USING (
    auth.uid() = seller_id OR
    public.is_order_buyer(order_id, auth.uid()) OR
    public.is_admin(auth.uid())
  );

CREATE POLICY "Allow insert on order_items for order buyer" ON public.order_items
  FOR INSERT TO authenticated WITH CHECK (
    public.is_order_buyer(order_id, auth.uid())
  );

CREATE POLICY "Allow update on order_items for seller, buyer, or admin" ON public.order_items
  FOR UPDATE TO authenticated USING (
    auth.uid() = seller_id OR
    public.is_order_buyer(order_id, auth.uid()) OR
    public.is_admin(auth.uid())
  );

-- Trigger to validate order_items price_at_purchase, force status to pending_payment, and pull correct seller_id
CREATE OR REPLACE FUNCTION public.validate_order_item_insert()
RETURNS TRIGGER AS $$
DECLARE
  v_product_price numeric;
  v_seller_id uuid;
BEGIN
  SELECT price, seller_id INTO v_product_price, v_seller_id
  FROM public.products
  WHERE id = NEW.product_id;

  IF v_product_price IS NULL THEN
    RAISE EXCEPTION 'Product with ID % does not exist', NEW.product_id;
  END IF;

  IF NEW.price_at_purchase <> v_product_price THEN
    RAISE EXCEPTION 'Price mismatch for product ID %. Expected %, got %', NEW.product_id, v_product_price, NEW.price_at_purchase;
  END IF;

  NEW.item_status := 'pending_payment';
  NEW.seller_id := v_seller_id;
  NEW.payout_released := false;
  NEW.delivered_at := NULL;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_order_item_inserted_validate
  BEFORE INSERT ON public.order_items
  FOR EACH ROW EXECUTE FUNCTION public.validate_order_item_insert();

-- Trigger to restrict order_items updates (strict transition controls)
CREATE OR REPLACE FUNCTION public.enforce_order_item_update_restrictions()
RETURNS TRIGGER AS $$
DECLARE
  v_user_role text;
BEGIN
  SELECT role INTO v_user_role FROM public.profiles WHERE id = auth.uid();

  -- Admins can update anything
  IF v_user_role = 'admin' THEN
    RETURN NEW;
  END IF;

  -- Non-admins cannot modify fields other than item_status and delivered_at
  -- (Allow product_id to become NULL if the product has been deleted)
  IF (NEW.id IS DISTINCT FROM OLD.id OR
      NEW.order_id IS DISTINCT FROM OLD.order_id OR
      (NEW.product_id IS DISTINCT FROM OLD.product_id AND (NEW.product_id IS NOT NULL OR EXISTS (SELECT 1 FROM public.products WHERE id = OLD.product_id))) OR
      NEW.seller_id IS DISTINCT FROM OLD.seller_id OR
      NEW.quantity IS DISTINCT FROM OLD.quantity OR
      NEW.price_at_purchase IS DISTINCT FROM OLD.price_at_purchase OR
      NEW.payout_released IS DISTINCT FROM OLD.payout_released) THEN
    RAISE EXCEPTION 'Non-admins can only modify item_status and delivered_at';
  END IF;

  -- If status is not changing, allow the update (e.g. product deletion setting product_id to NULL)
  IF NEW.item_status IS NOT DISTINCT FROM OLD.item_status THEN
    IF auth.uid() = OLD.seller_id AND NEW.delivered_at IS DISTINCT FROM OLD.delivered_at THEN
      RAISE EXCEPTION 'Sellers cannot modify delivered_at';
    END IF;
    RETURN NEW;
  END IF;

  -- Approve updates if explicitly bypassed by secure server-side functions
  IF current_setting('app.order_completion', true) = 'true' OR current_setting('app.payment_settlement', true) = 'true' THEN
    RETURN NEW;
  END IF;

  -- Reject any direct attempt to set status to 'completed' or 'paid_escrow'
  IF NEW.item_status = 'completed' THEN
    RAISE EXCEPTION 'Cannot manually transition item status to completed. Must elapse through return window.';
  END IF;

  IF NEW.item_status = 'paid_escrow' THEN
    RAISE EXCEPTION 'Cannot manually set status to paid_escrow. Must trigger via payment webhook.';
  END IF;

  -- Sellers can only transition: paid_escrow -> shipped
  IF auth.uid() = OLD.seller_id THEN
    IF OLD.item_status = 'paid_escrow' AND NEW.item_status = 'shipped' THEN
      IF NEW.delivered_at IS DISTINCT FROM OLD.delivered_at THEN
        RAISE EXCEPTION 'Sellers cannot modify delivered_at';
      END IF;
      RETURN NEW;
    ELSE
      RAISE EXCEPTION 'Invalid status transition for seller: % -> %', OLD.item_status, NEW.item_status;
    END IF;
  END IF;

  -- Buyers can only transition: shipped -> return_window | return_window -> disputed
  IF auth.uid() = (SELECT buyer_id FROM public.orders WHERE id = OLD.order_id) THEN
    IF OLD.item_status = 'shipped' AND NEW.item_status = 'return_window' THEN
      IF NEW.delivered_at IS NULL THEN
        RAISE EXCEPTION 'delivered_at must be populated when transitioning to return_window';
      END IF;
      RETURN NEW;
    ELSIF OLD.item_status = 'return_window' AND NEW.item_status = 'disputed' THEN
      IF NEW.delivered_at IS DISTINCT FROM OLD.delivered_at THEN
        RAISE EXCEPTION 'delivered_at cannot be modified';
      END IF;
      RETURN NEW;
    ELSE
      RAISE EXCEPTION 'Invalid status transition for buyer: % -> %', OLD.item_status, NEW.item_status;
    END IF;
  END IF;

  RAISE EXCEPTION 'Unauthorized to update this order item';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_order_item_updated_restricted
  BEFORE UPDATE ON public.order_items
  FOR EACH ROW EXECUTE FUNCTION public.enforce_order_item_update_restrictions();

-- ----------------------------------------------------
-- 6. PAYOUTS TABLE & POLICIES
-- ----------------------------------------------------

CREATE TABLE IF NOT EXISTS public.payouts (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  seller_id uuid REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
  period_start timestamp with time zone NOT NULL,
  period_end timestamp with time zone NOT NULL,
  total_amount numeric NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid')),
  paid_at timestamp with time zone,
  paid_by uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS
ALTER TABLE public.payouts ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY "Allow select on payouts for seller or admin" ON public.payouts
  FOR SELECT TO authenticated USING (auth.uid() = seller_id OR public.is_admin(auth.uid()));

CREATE POLICY "Allow all on payouts for admin only" ON public.payouts
  FOR ALL TO authenticated USING (public.is_admin(auth.uid()));

-- ----------------------------------------------------
-- 6a. PAYOUT SETTINGS LOG & POLICIES
-- ----------------------------------------------------

CREATE TABLE IF NOT EXISTS public.payout_settings_log (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  seller_id uuid REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
  old_details text,
  new_details text,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS
ALTER TABLE public.payout_settings_log ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY "Allow select on payout_settings_log for owner or admin" ON public.payout_settings_log
  FOR SELECT TO authenticated USING (auth.uid() = seller_id OR public.is_admin(auth.uid()));

CREATE POLICY "Allow insert on payout_settings_log for owner" ON public.payout_settings_log
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = seller_id);

-- Trigger to log payout details change automatically
CREATE OR REPLACE FUNCTION public.log_payout_details_change()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.bank_account_details IS DISTINCT FROM OLD.bank_account_details THEN
    INSERT INTO public.payout_settings_log (seller_id, old_details, new_details)
    VALUES (NEW.id, OLD.bank_account_details, NEW.bank_account_details);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_payout_details_updated
  AFTER UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.log_payout_details_change();


-- ----------------------------------------------------
-- 7. REVIEWS TABLE
-- ----------------------------------------------------

CREATE TABLE IF NOT EXISTS public.reviews (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  product_id bigint REFERENCES public.products(id) ON DELETE CASCADE NOT NULL,
  name text NOT NULL,
  email text NOT NULL,
  rating integer NOT NULL CHECK (rating >= 1 AND rating <= 5),
  comment text NOT NULL,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS
ALTER TABLE public.reviews ENABLE ROW LEVEL SECURITY;

-- Policies
DROP POLICY IF EXISTS "Enable read access for everyone" ON public.reviews;
CREATE POLICY "Enable read access for everyone"
ON public.reviews FOR SELECT TO public USING (true);

DROP POLICY IF EXISTS "Enable insert access for everyone" ON public.reviews;
CREATE POLICY "Enable insert access for everyone"
ON public.reviews FOR INSERT TO public WITH CHECK (true);

-- ----------------------------------------------------
-- 8. SYSTEM & SECURITY DEFINER INTERFACE FUNCTIONS
-- ----------------------------------------------------

-- Settle payment (called by webhook Edge Function / local simulator)
CREATE OR REPLACE FUNCTION public.confirm_payment_via_webhook(
  p_order_ref text,
  p_payment_method text,
  p_payment_reference text
)
RETURNS void AS $$
DECLARE
  v_current_status text;
  v_calculated_total numeric;
  v_order_id uuid;
BEGIN
  -- Restrict execution to service_role or admin
  IF auth.role() <> 'service_role' AND NOT public.is_admin(auth.uid()) THEN
    RAISE EXCEPTION 'Unauthorized: Only service_role or admin can confirm payment';
  END IF;

  SELECT id, status INTO v_order_id, v_current_status FROM public.orders WHERE order_ref = p_order_ref;
  IF v_order_id IS NULL THEN
    RAISE EXCEPTION 'Order not found';
  END IF;

  -- Idempotency check: Skip if already paid/processed
  IF v_current_status IN ('paid_escrow', 'shipped', 'delivered', 'return_window', 'completed', 'disputed', 'refunded') THEN
    RETURN;
  END IF;

  -- Recalculate order total from actual line items to lock correctness (ignoring client-supplied total)
  SELECT COALESCE(SUM(price_at_purchase * quantity), 0) + 250 INTO v_calculated_total
  FROM public.order_items
  WHERE order_id = v_order_id;

  -- Bypass trigger block by enabling session context flag
  PERFORM set_config('app.payment_settlement', 'true', true);

  -- Settle the order payment method, reference, status, and recalculate total
  UPDATE public.orders
  SET status = 'paid_escrow',
      payment_method = p_payment_method,
      payment_reference = p_payment_reference,
      total_amount = v_calculated_total
  WHERE id = v_order_id;

  -- Settle the status for individual order items
  UPDATE public.order_items
  SET item_status = 'paid_escrow'
  WHERE order_id = v_order_id;

  -- Asynchronously trigger payment received notification to platform owner
  DECLARE
    v_anon_key text;
    v_webhook_secret text;
  BEGIN
    SELECT decrypted_secret INTO v_anon_key FROM vault.decrypted_secrets WHERE name = 'anon_key';
    SELECT decrypted_secret INTO v_webhook_secret FROM vault.decrypted_secrets WHERE name = 'internal_webhook_secret';

    PERFORM net.http_post(
      url := 'https://goguiruuirltoiofmvuj.supabase.co/functions/v1/send-owner-notification',
      headers := jsonb_build_object(
        'Content-Type', 'application/json',
        'Authorization', 'Bearer ' || v_anon_key,
        'x-internal-webhook-secret', v_webhook_secret
      ),
      body := jsonb_build_object(
        'type', 'payment_received',
        'order_id', v_order_id
      )
    );
  EXCEPTION WHEN OTHERS THEN
    -- Prevent failures in notifications from rolling back the payment transaction
    RAISE WARNING 'Failed to trigger payment received email notification: %', SQLERRM;
  END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Auto-complete order item (return-window closure)
CREATE OR REPLACE FUNCTION public.auto_complete_order_item(
  p_item_id bigint,
  p_bypass_time_check_for_testing boolean DEFAULT false
)
RETURNS void AS $$
DECLARE
  v_status text;
  v_delivered_at timestamp with time zone;
BEGIN
  -- Restrict execution to service_role or admin
  IF auth.role() <> 'service_role' AND NOT public.is_admin(auth.uid()) THEN
    RAISE EXCEPTION 'Unauthorized: Only service_role or admin can complete order items';
  END IF;

  SELECT item_status, delivered_at INTO v_status, v_delivered_at
  FROM public.order_items
  WHERE id = p_item_id;

  IF v_status IS NULL THEN
    RAISE EXCEPTION 'Order item not found';
  END IF;

  IF v_status <> 'return_window' THEN
    RAISE EXCEPTION 'Item status is %, expected return_window', v_status;
  END IF;

  -- Time check
  IF now() - v_delivered_at < interval '3 days' THEN
    -- Allow bypass ONLY if test flag is true AND DB dev mode custom setting is active in settings table
    IF p_bypass_time_check_for_testing AND public.is_dev_mode() THEN
      -- Proceed with completion for testing
    ELSE
      RAISE EXCEPTION 'Return window has not elapsed yet';
    END IF;
  END IF;

  -- Bypass trigger block
  PERFORM set_config('app.order_completion', 'true', true);

  UPDATE public.order_items
  SET item_status = 'completed'
  WHERE id = p_item_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ----------------------------------------------------
-- 9. STORAGE BUCKET CONFIGURATION
-- ----------------------------------------------------

INSERT INTO storage.buckets (id, name, public)
VALUES ('product-images', 'product-images', true)
ON CONFLICT (id) DO NOTHING;

DROP POLICY IF EXISTS "Allow public read access to product-images" ON storage.objects;
CREATE POLICY "Allow public read access to product-images" ON storage.objects
  FOR SELECT TO public USING (bucket_id = 'product-images');

DROP POLICY IF EXISTS "Allow approved sellers to upload product-images" ON storage.objects;
CREATE POLICY "Allow approved sellers to upload product-images" ON storage.objects
  FOR INSERT TO authenticated WITH CHECK (
    bucket_id = 'product-images' AND
    (SELECT role FROM public.profiles WHERE id = auth.uid()) = 'seller' AND
    (SELECT seller_status FROM public.profiles WHERE id = auth.uid()) = 'approved'
  );

-- Reset products ID identity sequence to start fresh
ALTER TABLE public.products ALTER COLUMN id RESTART WITH 1;

-- ----------------------------------------------------
-- 11. DEDICATED ADMIN DASHBOARD SCHEMA ADDITIONS
-- ----------------------------------------------------

-- Add is_hidden column to products
ALTER TABLE public.products ADD COLUMN IF NOT EXISTS is_hidden boolean NOT NULL DEFAULT false;

-- Re-create public_products view to filter out hidden products and products from suspended sellers
CREATE OR REPLACE VIEW public.public_products AS
  SELECT
    p.id,
    p.name,
    p.description,
    p.price,
    p.original_price,
    p.category,
    p.category_key,
    p.images,
    p.colors,
    p.sizes,
    p.specs,
    p.verified_badge,
    p.stock_status,
    p.gradient,
    p.featured,
    p.created_at
  FROM public.products p
  LEFT JOIN public.profiles s ON p.seller_id = s.id
  WHERE p.is_hidden = false AND (p.seller_id IS NULL OR s.seller_status <> 'suspended');

GRANT SELECT ON public.public_products TO anon, authenticated;

-- Create seller score adjustment log table
CREATE TABLE IF NOT EXISTS public.seller_score_log (
  id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  seller_id uuid REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
  old_score numeric NOT NULL,
  new_score numeric NOT NULL,
  reason text NOT NULL,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS on seller_score_log
ALTER TABLE public.seller_score_log ENABLE ROW LEVEL SECURITY;

-- Allow select to owner or admin
CREATE POLICY "Allow select on seller_score_log for owner or admin" ON public.seller_score_log
  FOR SELECT TO authenticated USING (auth.uid() = seller_id OR public.is_admin(auth.uid()));

-- Allow insert to admin only
CREATE POLICY "Allow insert on seller_score_log for admin only" ON public.seller_score_log
  FOR INSERT TO authenticated WITH CHECK (public.is_admin(auth.uid()));

-- Create payout batch RPC function
CREATE OR REPLACE FUNCTION public.run_payout_batch(
  p_start_date timestamp with time zone,
  p_end_date timestamp with time zone
)
RETURNS void AS $$
DECLARE
  v_caller_role text;
BEGIN
  -- Check if caller is admin
  SELECT role INTO v_caller_role FROM public.profiles WHERE id = auth.uid();
  IF v_caller_role <> 'admin' OR v_caller_role IS NULL THEN
    RAISE EXCEPTION 'Unauthorized: Only administrators can run payout batches';
  END IF;

  -- Insert grouped payouts
  INSERT INTO public.payouts (seller_id, period_start, period_end, total_amount, status)
  SELECT 
    seller_id, 
    p_start_date, 
    p_end_date, 
    SUM(price_at_purchase * quantity) as total_amount, 
    'pending'
  FROM public.order_items
  WHERE item_status = 'completed' 
    AND payout_released = false 
    AND created_at >= p_start_date 
    AND created_at <= p_end_date
  GROUP BY seller_id;

  -- Mark order items as released
  UPDATE public.order_items
  SET payout_released = true
  WHERE item_status = 'completed' 
    AND payout_released = false 
    AND created_at >= p_start_date 
    AND created_at <= p_end_date;
    
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

