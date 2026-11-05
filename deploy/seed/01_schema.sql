-- pgsafe dev seed: schema of a simulated Thai online shop (design doc §8).
-- Same SQL is used for PostgreSQL 14, 16 and 18.

CREATE TABLE products (
    id          integer PRIMARY KEY,
    sku         text NOT NULL UNIQUE,
    name        text NOT NULL,
    price       numeric(10,2) NOT NULL,
    created_at  timestamptz NOT NULL
);

CREATE TABLE customers (
    id           integer PRIMARY KEY,
    title        text NOT NULL,
    first_name   text NOT NULL,
    last_name    text NOT NULL,
    full_name    text NOT NULL,
    email        text NOT NULL UNIQUE,
    phone        text NOT NULL,
    citizen_id   char(13) NOT NULL UNIQUE,
    birth_date   date NOT NULL,
    address      text NOT NULL,
    postal_code  char(5) NOT NULL,
    province     text NOT NULL,
    tier         text NOT NULL,
    preferences  jsonb NOT NULL DEFAULT '{}',
    notes        text,
    created_at   timestamptz NOT NULL
);
COMMENT ON COLUMN customers.full_name  IS 'ชื่อ-นามสกุลลูกค้า';
COMMENT ON COLUMN customers.citizen_id IS 'เลขบัตรประจำตัวประชาชน';
COMMENT ON COLUMN customers.phone      IS 'เบอร์โทรศัพท์มือถือ';
COMMENT ON COLUMN customers.address    IS 'ที่อยู่สำหรับจัดส่ง';
COMMENT ON COLUMN customers.tier       IS 'ระดับสมาชิก';

CREATE TABLE orders (
    id                integer PRIMARY KEY,
    customer_id       integer NOT NULL REFERENCES customers(id),
    customer_email    text NOT NULL,   -- duplicated on purpose: deterministic masking must keep joins working
    status            text NOT NULL,
    total             numeric(12,2) NOT NULL,
    shipping_address  text NOT NULL,
    created_at        timestamptz NOT NULL
);
CREATE INDEX orders_customer_id_idx ON orders (customer_id);
CREATE INDEX orders_created_at_idx  ON orders (created_at);

CREATE TABLE order_items (
    id          integer PRIMARY KEY,
    order_id    integer NOT NULL REFERENCES orders(id),
    product_id  integer NOT NULL REFERENCES products(id),
    qty         integer NOT NULL CHECK (qty > 0),
    unit_price  numeric(10,2) NOT NULL
);
CREATE INDEX order_items_order_id_idx ON order_items (order_id);

CREATE TABLE payments (
    id           integer PRIMARY KEY,
    order_id     integer NOT NULL UNIQUE REFERENCES orders(id),
    method       text NOT NULL,
    card_number  text,
    card_last4   char(4),
    amount       numeric(12,2) NOT NULL,
    payer_ip     inet NOT NULL,
    paid_at      timestamptz NOT NULL
);

-- Tables used to exercise exclude_tables / exclude_table_data / truncate.
CREATE TABLE sessions (
    id           uuid PRIMARY KEY,
    customer_id  integer NOT NULL REFERENCES customers(id),
    token        text NOT NULL,
    created_at   timestamptz NOT NULL
);

CREATE TABLE cache_pages (
    key   text PRIMARY KEY,
    body  text NOT NULL
);

CREATE TABLE audit_raw_logs (
    id          integer PRIMARY KEY,
    payload     jsonb NOT NULL,
    created_at  timestamptz NOT NULL
);
