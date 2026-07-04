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
  seller_status text NOT NULL DEFAULT 'none' CHECK (seller_status IN ('none', 'pending', 'approved', 'suspended')),
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

CREATE POLICY "Allow public read access to product-images" ON storage.objects
  FOR SELECT TO public USING (bucket_id = 'product-images');

CREATE POLICY "Allow approved sellers to upload product-images" ON storage.objects
  FOR INSERT TO authenticated WITH CHECK (
    bucket_id = 'product-images' AND
    (SELECT role FROM public.profiles WHERE id = auth.uid()) = 'seller' AND
    (SELECT seller_status FROM public.profiles WHERE id = auth.uid()) = 'approved'
  );

-- ----------------------------------------------------
-- 10. SEED DATA FOR PRODUCTS
-- ----------------------------------------------------

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (1, 'Premium Christian Dior Inspired Export Leftover Cotton Tee', 'Upgrade your casual wardrobe with this ultra-comfortable, high-quality Export Leftover Graphic Tee. Featuring a minimalist and stylish Christian Dior inspired design across the chest, this t-shirt offers a high-end designer aesthetic at an unbeatable budget-friendly price.

Made from premium, breathable cotton fabric, it''s engineered to keep you cool and comfortable all day long. Perfect for daily wear, gym sessions, or casual hangouts with friends.

💎 Premium Export Quality: Get authentic export-grade stitching and fabric durability at a fraction of retail cost!', 600, NULL, 'Apparel & Fashion', 'apparel-fashion', ARRAY['images/products/shirts/Item 1/1.png'], ARRAY['#98d4a6', '#ffffff'], ARRAY['M', 'L', 'XL'], '{"Fabric":"100% Premium Breathable Cotton","Design":"C. Dior / Christian typography graphic print","Stock Category":"Premium Export Leftover","Color":"Mint Green, Classic White","Size":"Medium (M), Large (L), Extra Large (XL)","Fit":"Regular / Standard Comfort Fit"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (2, 'Premium Calligraphy Print Graphic Tee – "Mir" Design', 'Elevate your everyday street style with our exclusive Arabic Calligraphy Graphic Tee. Featuring the bold, elegant text "میر" (Mir) across the chest, this t-shirt perfectly blends traditional cultural art with modern fashion aesthetics.

Crafted with eye-catching geometric border accents running vertically down the front and along the hem, this piece offers a unique, structured look. The relaxed-fit cut ensures maximum comfort, making it a perfect choice for casual outings, daily wear, or layering.

⚠️ Hurry! Limited stock available. Grab yours before it''s gone!', 900, NULL, 'Apparel & Fashion', 'apparel-fashion', ARRAY['images/products/shirts/Item 2/1.png'], ARRAY['#d32f2f', '#2e7d32', '#1976d2', '#ffffff', '#5d4037'], ARRAY['L', 'XL'], '{"Design":"Arabic/Urdu Calligraphy text (\"میر\") with geometric tribal-inspired borders","Color":"Red, Green, Blue, White, Brown (Dusty pink/rose shown)","Size":"Large (L), Extra Large (XL)","Fit":"Relaxed / Regular fit","Neckline":"Classic Crew Neck","Sleeves":"Half Sleeves with printed border details"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #d4a5a5 0%, #c48b8b 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (3, '"Country Every Day" Premium Export Leftover Cotton Tee – Vibrant Red', 'Inject a burst of energy into your casual rotation with this high-comfort Export Leftover Graphic Tee. Featuring a clean, modern white script design that reads "Country Every Day" accented by minimalist blue and white athletic stripes, this shirt strikes the perfect balance between sporty and casual.

Crafted from premium, export-grade cotton fabric, it offers a soft hand-feel and superior breathability. It''s the ideal go-to choice for effortless daily style, layering, or weekend hangouts.

💎 Export Leftover Deal: Enjoy authentic export-quality stitching, premium fabric, and retail-grade durability for just 600 RS!', 600, NULL, 'Apparel & Fashion', 'apparel-fashion', ARRAY['images/products/shirts/Item 3/1.png'], ARRAY['#d32f2f'], ARRAY['M', 'L'], '{"Fabric":"100% Premium Breathable Cotton","Design":"\"Country Every Day\" contemporary script with minimalist color accents","Stock Category":"Premium Export Leftover","Color":"Vibrant Red","Size":"Medium (M), Large (L) (XL out of stock)","Fit":"Regular / Standard Comfort Fit"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #ef5350 0%, #e53935 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (4, '"Country Every Day" Premium Export Leftover Cotton Tee – Vibrant Red', 'Inject a burst of energy into your casual rotation with this high-comfort Export Leftover Graphic Tee. Featuring a clean, modern white script design that reads "Country Every Day" accented by minimalist blue and white athletic stripes, this shirt strikes the perfect balance between sporty and casual.

Crafted from premium, export-grade cotton fabric, it offers a soft hand-feel and superior breathability. It''s the ideal go-to choice for effortless daily style, layering, or weekend hangouts.

💎 Export Leftover Deal: Enjoy authentic export-quality stitching, premium fabric, and retail-grade durability for just 600 RS!', 600, NULL, 'Apparel & Fashion', 'apparel-fashion', ARRAY['images/products/shirts/Item 4/1.png'], ARRAY['#d32f2f', '#f5f5f0'], ARRAY['M', 'L'], '{"Fabric Material":"100% Premium Breathable Cotton","Design/Theme":"\"Country Every Day\" contemporary script with minimalist color accents","Stock Category":"Premium Export Leftover","Available Color":"off white and Vibrant Red","Available Sizes":"Medium (M), Large (L) (XL out of stock)","Fit":"Regular / Standard Comfort Fit","Price":"600 RS Only","Key Features":"Breathable Premium Cotton, High-Definition Print, Unbeatable Value"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #ef5350 0%, #e53935 100%)', false)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (5, '"Nice, nice." Premium Export Leftover Cotton Tee – Jet Black', 'Keep it effortlessly cool and casual with this Premium Export Leftover Graphic Tee. Featuring a minimalist, modern typography design that reads "Nice, nice." in a clean mix of white and sky-blue lettering, this shirt is the perfect casual statement piece.

Made from premium, export-grade cotton fabric, it gives you that ultra-soft feel against the skin and excellent breathability for all-day comfort. Designed with durable, clean stitching, it maintains its sharp look and pitch-black color wash after wash.

⚡ EXCLUSIVE BUNDLE DEAL: Buy 1 for just 600 RS, or smart-shop our Pack of 4 for only 2200 RS to mix, match, and save big before stock runs out!', 600, 750, 'Apparel & Fashion', 'apparel-fashion', ARRAY['images/products/shirts/Item 5/1.png'], ARRAY['#1a1a1a'], ARRAY['M', 'L'], '{"Fabric":"100% Premium Export-Grade Cotton","Design":"\"Nice, nice.\" minimalist modern typography print","Stock Category":"Premium Export Leftover","Color":"Jet Black","Size":"Medium (M), Large (L) (XL out of stock)","Fit":"Standard Comfort Fit","Bulk Offer":"4 for Rs 2200"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #2d2d2d 0%, #1a1a1a 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (6, 'Premium Calvin Klein Inspired Export Leftover Cotton Tee – Cream', 'Embrace effortless luxury and clean aesthetics with this Export Leftover Graphic Tee. Featuring the iconic, minimalist Calvin Klein typography across the chest, this t-shirt brings a high-end designer look to your everyday rotation without breaking the bank.

Crafted from premium, export-grade cotton fabric in a versatile off-white/cream shade, it offers a soft-to-the-touch feel and maximum breathability. It''s the ultimate wardrobe staple that pairs perfectly with denim, joggers, or layered under a jacket.

💎 Premium Export Quality: Enjoy authentic retail-grade fabric, precise stitching, and high durability for just 600 RS!', 600, 750, 'Apparel & Fashion', 'apparel-fashion', ARRAY['images/products/shirts/Item 6/1.png'], ARRAY['#f5f0e8'], ARRAY['M', 'L'], '{"Fabric":"100% Premium Breathable Cotton","Design":"Minimalist Calvin Klein typography graphic print","Stock Category":"Premium Export Leftover","Color":"Cream / Off-White","Size":"Medium (M), Large (L) (XL out of stock)","Fit":"Regular / Standard Comfort Fit"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #faf5ef 0%, #f0e8dc 100%)', false)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (7, '"NOW" Motivational Print Premium Export Leftover Cotton Tee – Mint Green', 'Make every moment count with this stylish and thought-provoking Export Leftover Graphic Tee. Featuring a bold, contemporary typography design that crosses out Yesterday and Tomorrow to highlight "NOW", this shirt brings an inspiring, modern streetwear vibe to your wardrobe.

Crafted from top-grade, premium export cotton, it features a highly breathable fabric weave that ensures ultra-soft comfort all day long. Its vibrant mint green shade serves as a perfect conversational staple for gym sessions, casual hangouts, or daily streetwear styling.

💎 Premium Export Quality: Get authentic export-grade stitching, retail durability, and a premium hand-feel for just 600 RS!', 600, 750, 'Apparel & Fashion', 'apparel-fashion', ARRAY['images/products/shirts/Item 7/1.png'], ARRAY['#98d4a6'], ARRAY['M', 'L'], '{"Fabric":"100% Premium Breathable Cotton","Design":"Contemporary \"NOW\" box typography with struck-through motivational script","Stock Category":"Premium Export Leftover","Color":"Mint Green","Size":"Medium (M), Large (L) (XL out of stock)","Fit":"Regular / Standard Comfort Fit"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #e0f2f1 0%, #b2dfdb 100%)', false)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (8, '"DREAM 1976" Vintage Athletic Premium Export Leftover Cotton Tee – Light Gray', 'Add a classic varsity vibe to your daily look with this Export Leftover Graphic Tee. Featuring a bold "DREAM 1976" retro athletic design complete with interlocking rings, varsity stripes, and clean typography accents, this shirt delivers the perfect casual, collegiate aesthetic.

Crafted from top-tier, export-grade cotton fabric in an incredibly versatile light gray heather shade, it offers premium breathability and an ultra-soft hand-feel. It''s the ideal go-to staple for effortless styling, layering under denim jackets, or hitting the streets in comfort.

💎 Export Leftover Quality: Experience authentic premium retail fabric, durable dual-needle stitching, and high longevity for an incredible price of just 600 RS!', 600, NULL, 'Apparel & Fashion', 'apparel-fashion', ARRAY['images/products/shirts/Item 8/1.png'], ARRAY['#c0c0c0'], ARRAY['M', 'L'], '{"Fabric":"100% Premium Breathable Cotton","Design":"Retro varsity athletic \"DREAM 1976\" print with geometric interlocking accents","Stock Category":"Premium Export Leftover","Color":"Light Gray / Ash Gray","Size":"Medium (M), Large (L) (XL out of stock)","Fit":"Standard / Regular Comfort Fit"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #f5f5f5 0%, #e0e0e0 100%)', false)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (9, '"EXTRA LIFE" Retro Gaming Inspired Export Leftover Cotton Tee – Classic White', 'Level up your casual wardrobe with this ultra-comfortable Export Leftover Graphic Tee. Featuring a clean, retro-arcade inspired chest print that reads "EXTRA LIFE" alongside vibrant blue speed stripes and a minimalist gaming mascot motif, this shirt brings an effortless, playful streetwear vibe to your daily look.

Crafted from premium, export-grade cotton fabric, it delivers a soft-to-the-touch feel and high breathability to keep you cool all day. The classic white base makes it incredibly versatile, easily pairing with blue denim, dark cargos, or casual summer shorts.

💎 Premium Export Quality: Get authentic export-grade fabric, precise double-needle stitching, and durable retail-level quality for an incredible price of just 600 RS!', 600, 750, 'Apparel & Fashion', 'apparel-fashion', ARRAY['images/products/shirts/Item 9/1.png'], ARRAY['#ffffff'], ARRAY['M', 'L'], '{"Fabric":"100% Premium Breathable Cotton","Design":"Retro arcade \"EXTRA LIFE\" typography with blue racing stripes and mascot motif","Stock Category":"Premium Export Leftover","Color":"Classic White / Off-White","Size":"Medium (M), Large (L) (XL out of stock)","Fit":"Regular / Standard Comfort Fit"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #fafafa 0%, #eeeeee 100%)', false)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (11, '"Aura Midnight" Minimalist All-Black Arabic Dial Watch – Jet Black Edition', 'Master the art of understated elegance with the Aura Midnight Edition. This sleek, monochromatic timepiece is designed for those who appreciate a bold, minimalist aesthetic. Featuring a clean, striking matte black dial with distinct Arabic numerals, it brings an effortless, contemporary edge to your wrist.

Crafted with a lightweight yet highly durable build, it offers exceptional comfort for all-day wear. It’s the perfect versatile accessory—easy to pair with casual street style, sharp office wear, or a formal blazer for a clean, sophisticated look.

💎 Premium Fashion Deal: Enjoy high-end minimalist design, a premium butterfly clasp, and sleek aesthetics for an unbeatable price of just 999 RS!', 850, 1200, 'Accessories & Jewelry', 'accessories-jewelry', ARRAY['images/products/watches/Item 1/1.png'], ARRAY['#000000'], ARRAY['Fiber Strap', 'Steel Chain'], '{"Color/Theme":"Matte Jet Black (Full Monochromatic)","Dial Style":"Minimalist with unique Arabic numerals","Movement":"Precision Analog Quartz Movement","Strap Material":"Premium Lightweight Fiber / Stainless Steel Chain","Clasp Type":"Secure Butterfly Deployment Clasp","Gender":"Unisex (Designed for both Men & Women)","Fit":"Adjustable Link Strap for a standard, comfortable fit"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #1f2937 0%, #111827 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (12, '"Aura Pristine" Minimalist All-White Analog Watch – Classic Frost Edition', 'Embrace a clean, ultra-modern aesthetic with the Aura Pristine Edition. This timeless timepiece is designed for those who appreciate sleek, minimalist style. Featuring a brilliant, sharp white dial housed in a polished casing, it brings a fresh, bright look that instantly coordinates with your wardrobe.

Crafted with a lightweight yet durable build, it ensures exceptional comfort for all-day wear. It’s the ultimate everyday accessory—perfect for adding a sharp, polished touch to casual street style, bright summer fits, or clean professional outfits.

💎 Premium Fashion Deal: Enjoy high-end minimalist design, a premium butterfly clasp, and pristine aesthetics for an unbeatable price of just 999 RS!', 850, 1200, 'Accessories & Jewelry', 'accessories-jewelry', ARRAY['images/products/watches/Item 2/1.jpg'], ARRAY['#ffffff'], ARRAY['Fiber Strap', 'Steel Chain'], '{"Color/Theme":"Classic Frost White (Full Monochromatic Layout)","Dial Style":"Minimalist with subtle index markers / numeric layout","Movement":"Precision Analog Quartz Movement","Strap Material":"Premium Lightweight Fiber / Stainless Steel Chain","Clasp Type":"Secure Butterfly Deployment Clasp","Gender":"Unisex (Designed for both Men & Women)","Fit":"Adjustable Link Strap for a standard, comfortable fit"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (13, '"Sub-Mariner Elite" Two-Tone Luxury Watch - Classic Sea-Dweller Edition', 'Command attention with a timepiece that exudes ultimate luxury and rugged sophistication. Inspired by legendary deep-sea designs, this premium watch perfectly captures an iconic two-tone aesthetic. Featuring a bold black dial beautifully contrasted by a polished gold and silver steel casing, it brings an instant upgrade to any wardrobe.

The striking unidirectional rotating bezel features crisp gold numbering, allowing you to track time with professional precision. Complete with a magnified date window at the 3 o''clock position, it seamlessly blends high-end functionality with a timeless executive style.

Premium Fashion Deal: Enjoy the legendary aesthetic of a two-tone luxury dive watch, a robust rotating bezel, and a heavy-duty steel chain for an unbeatable price of just 3,500 RS!', 2800, 3500, 'Accessories & Jewelry', 'accessories-jewelry', ARRAY['images/products/watches/Item 3/1.jpeg'], ARRAY['linear-gradient(135deg, #111827 0%, #111827 34%, #d4af37 34%, #d4af37 67%, #c0c0c0 67%, #c0c0c0 100%)'], ARRAY['Steel Chain'], '{"Color/Theme":"Luxury Two-Tone (Polished Gold & Premium Silver Steel)","Dial Style":"Deep Black with luminous geometric index markers and a magnified date cyclops window","Bezel":"Fully functional, unidirectional rotating dive bezel with gold accents","Movement":"Precision Analog Quartz / Battery Powered","Strap Material":"Premium Two-Tone Stainless Steel Oyster Chain","Clasp Type":"Secure Folding Oysterlock Safety Clasp","Gender":"Men / Unisex Executive Wear","Fit":"Adjustable Link Strap for a weighted, premium feel on the wrist"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #111827 0%, #d4af37 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (14, '"Oyster Presidential" Two-Tone Luxury Watch - Red Dial Edition', 'Make a bold statement with a timepiece that redefines executive luxury. This premium watch showcases the legendary fluted gold bezel design paired with a jaw-dropping, sunburst cherry-red dial. The rich gradient face shifts beautifully under the light, perfectly complemented by a polished two-tone gold and silver steel casing.

The striking watch dial features brilliant diamond-style index hour markers that give it an unmistakable, ultra-premium presence on the wrist. Complete with a signature magnified date window at the 3 o''clock position and gold-toned hands, it effortlessly delivers a masterpiece look that commands attention.

Premium Fashion Deal: Enjoy the legendary aesthetic of a two-tone fluted luxury watch, diamond-style index markers, and a premium steel chain for an unbeatable price of just 3,500 RS!', 2800, 3500, 'Accessories & Jewelry', 'accessories-jewelry', ARRAY['images/products/watches/Item 4/1.jfif'], ARRAY['linear-gradient(135deg, #7f1d1d 0%, #7f1d1d 34%, #d4af37 34%, #d4af37 67%, #c0c0c0 67%, #c0c0c0 100%)'], ARRAY['Steel Chain'], '{"Color/Theme":"Luxury Two-Tone (Polished Gold Fluted Bezel & Premium Silver Steel)","Dial Style":"Radiant Gradient Sunburst Red with diamond-style luxury markers and a magnified date cyclops window","Bezel":"Classic Iconic Fluted Executive Bezel with gold accents","Movement":"Precision Analog Quartz / Battery Powered","Strap Material":"Premium Two-Tone Stainless Steel Jubilee-Style Chain","Clasp Type":"Secure Folding Deployant Safety Clasp","Gender":"Men / Unisex Executive Wear","Fit":"Adjustable Link Strap for a solid, premium feel on the wrist"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #7f1d1d 0%, #d4af37 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (15, '"Trionda Pro Match" Premium Official Size 5 Football - Elite Edition', 'Bring tournament-level performance to your local pitch with a football designed for true enthusiasts. Featuring the stunning, multi-color dynamic panel graphics and metallic accents of the world''s biggest tournaments, this premium match ball is built to stand out. It showcases prestige branding alongside official match-grade styling that commands respect the moment it hits the field.

Engineered with textured surface panels for superior aerodynamic stability and a perfect grip, it offers exceptional ball control, true flight trajectories, and responsive power behind every strike. Whether you are running intense training drills, practicing your free kicks, or playing a high-stakes weekend match, this ball delivers top-tier durability and performance.

Premium Sports Deal: Enjoy elite-level textured panel construction, premium graphic styling, and tournament-grade performance for an unbeatable price of just 3,300 RS!', 3300, NULL, 'Sports & Outdoors', 'sports-outdoors', ARRAY['images/products/sports/football/Trionda/1.jpeg'], ARRAY['linear-gradient(135deg, #ffffff 0%, #ffffff 28%, #16a34a 28%, #16a34a 55%, #d4af37 55%, #d4af37 78%, #ef4444 78%, #ef4444 100%)'], ARRAY['Official Size 5'], '{"Color/Theme":"Vibrant Tournament Edition (Multi-Color Panels with Metallic Gold & Green Accents)","Size":"Official Size 5 (Standard Professional Match Size)","Construction":"High-performance textured casing for maximum grip and optimal aerodynamic flight","Bladder Type":"Premium High-Retention Butyl Bladder for long-lasting air and shape integrity","Suitability":"Perfect for both competitive matches and intensive training sessions","Playing Surface":"Ideal for Natural Grass and Modern Artificial Turf fields"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #ffffff 0%, #16a34a 45%, #d4af37 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

INSERT INTO public.products (id, name, description, price, original_price, category, category_key, images, colors, sizes, specs, seller_id, verified_badge, stock_status, gradient, featured)
VALUES (16, 'Hublot Classic Fusion Orlinski Edition – Geometric Skeleton Automatic Watch', 'Elevate your collection with a timepiece where high-end horology meets contemporary structural art. Inspired by renowned sculptural aesthetics, this watch features a signature 3D faceted case and a fully integrated geometric bracelet designed to catch the light from every angle.

The captivating open-heart skeleton dial reveals the intricate mechanical inner workings and gear trains, beautifully anchored by an exposed tourbillon-style balance wheel movement at the 6 o''clock position. Built for those who demand a bold, avant-garde aesthetic without compromising on mechanical allure.

Premium Features: Architectural Faceted Case with stunning multi-angled 3D geometric design, Open-Work Skeleton Dial showcasing precision gears, Premium Finishing available in striking Royal Blue and clean Arctic White, Signature H-shaped bezel accents with contrasting metallic hands.

Premium Fashion Deal: Enjoy a premium automatic skeleton mechanical timepiece with an integrated faceted bracelet for an unbeatable price of just 3,000 RS!', 3000, NULL, 'Accessories & Jewelry', 'accessories-jewelry', ARRAY['images/products/watches/Item 5/1.png'], ARRAY['#1e3a5f', '#f5f5f5'], ARRAY['Steel Chain'], '{"Color/Theme":"Royal Blue Ceramic / Arctic White Ceramic","Dial Style":"Skeleton / Transparent Mechanical Display","Movement":"Premium Automatic Mechanical Movement","Bracelet":"Integrated Matching Faceted Link Band","Clasp":"Secure Push-Button Deployment Clasp","Lens":"Scratch-Resistant Hardened Crystal","Case Back":"Transparent Exhibition View"}'::jsonb, NULL, true, 'available', 'linear-gradient(135deg, #1e3a5f 0%, #f5f5f5 100%)', true)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name, description = EXCLUDED.description, price = EXCLUDED.price, original_price = EXCLUDED.original_price, category = EXCLUDED.category, category_key = EXCLUDED.category_key, images = EXCLUDED.images, colors = EXCLUDED.colors, sizes = EXCLUDED.sizes, specs = EXCLUDED.specs, gradient = EXCLUDED.gradient, featured = EXCLUDED.featured;

-- Reset products ID identity sequence to start after the seeded items
ALTER TABLE public.products ALTER COLUMN id RESTART WITH 100;
