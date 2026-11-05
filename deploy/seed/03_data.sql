-- Deterministic data: exactly 100,000 rows in total.
--   products 1,000 | customers 20,000 | orders 50,000 | order_items 20,000
--   payments 8,000 | sessions 500 | cache_pages 200 | audit_raw_logs 300

INSERT INTO products (id, sku, name, price, created_at)
SELECT i,
       'SKU-' || lpad(i::text, 5, '0'),
       w.name || ' รุ่น ' || i,
       round((49 + seed.h(i, 1) % 4950)::numeric + (seed.h(i, 2) % 100) / 100.0, 2),
       timestamptz '2024-01-01 00:00:00+07' + i * interval '1 hour'
FROM generate_series(1, 1000) AS i
JOIN seed.product_words w ON w.n = 1 + seed.h(i, 3) % 10;

INSERT INTO customers (id, title, first_name, last_name, full_name, email, phone, citizen_id,
                       birth_date, address, postal_code, province, tier, preferences, notes, created_at)
SELECT i, x.title, f.th, l.th,
       x.title || f.th || ' ' || l.th,
       f.en || '.' || l.en || i || '@' || (ARRAY['gmail.com','hotmail.com','yahoo.co.th','outlook.co.th'])[1 + seed.h(i, 4) % 4],
       x.phone,
       -- 1 province digit + 5 hashed digits + 6-digit row number (unique) + checksum
       seed.thai_id_complete((1 + seed.h(i, 5) % 8)::text || lpad((seed.h(i, 6) % 100000)::text, 5, '0') || lpad(i::text, 6, '0')),
       date '1950-01-01' + (seed.h(i, 7) % 20000)::int,
       (1 + seed.h(i, 8) % 299) || '/' || (1 + seed.h(i, 9) % 99) || ' ถนน' || s.name || ' '
         || CASE WHEN a.bkk THEN 'แขวง' || a.subdistrict || ' เขต' || a.district || ' ' || a.province
                 ELSE 'ตำบล' || a.subdistrict || ' อำเภอ' || a.district || ' จังหวัด' || a.province END
         || ' ' || a.postal,
       a.postal, a.province,
       (ARRAY['bronze','silver','gold','platinum'])[1 + seed.h(i, 10) % 4],
       jsonb_build_object('newsletter', seed.h(i, 11) % 2 = 0, 'lang', 'th'),
       CASE seed.h(i, 12) % 10
            WHEN 0 THEN 'ลูกค้าขอให้โทรกลับที่ ' || x.phone
            WHEN 1 THEN 'ส่งใบกำกับภาษีไปที่ ' || f.en || '.' || l.en || i || '@gmail.com'
            WHEN 2 THEN 'ลูกค้าประจำ'
            ELSE NULL END,
       timestamptz '2024-01-01 00:00:00+07' + i * interval '20 minutes'
FROM generate_series(1, 20000) AS i
JOIN seed.first_names f ON f.n = 1 + seed.h(i, 13) % 20
JOIN seed.last_names  l ON l.n = 1 + seed.h(i, 14) % 12
JOIN seed.areas       a ON a.n = 1 + seed.h(i, 15) % 16
JOIN seed.streets     s ON s.n = 1 + seed.h(i, 16) % 10
CROSS JOIN LATERAL (
    SELECT CASE WHEN f.gender = 'M' THEN 'นาย'
                WHEN seed.h(i, 17) % 2 = 0 THEN 'นาง' ELSE 'นางสาว' END AS title,
           CASE WHEN seed.h(i, 18) % 10 = 0   -- 10% stored in +66 form
                THEN '+66' || (ARRAY['6','8','9'])[1 + seed.h(i, 19) % 3] || lpad((seed.h(i, 20) % 100000000)::text, 8, '0')
                ELSE '0'   || (ARRAY['6','8','9'])[1 + seed.h(i, 19) % 3] || lpad((seed.h(i, 20) % 100000000)::text, 8, '0')
           END AS phone
) x;

INSERT INTO orders (id, customer_id, customer_email, status, total, shipping_address, created_at)
SELECT i, c.id, c.email,
       (ARRAY['pending','paid','shipped','delivered','cancelled'])[1 + seed.h(i, 21) % 5],
       round((99 + seed.h(i, 22) % 20000)::numeric + (seed.h(i, 23) % 100) / 100.0, 2),
       c.address,
       timestamptz '2025-01-01 00:00:00+07' + i * interval '10 minutes'
FROM generate_series(1, 50000) AS i
JOIN customers c ON c.id = 1 + seed.h(i, 24) % 20000;

INSERT INTO order_items (id, order_id, product_id, qty, unit_price)
SELECT i, 1 + seed.h(i, 25) % 50000, p.id, 1 + seed.h(i, 26) % 5, p.price
FROM generate_series(1, 20000) AS i
JOIN products p ON p.id = 1 + seed.h(i, 27) % 1000;

INSERT INTO payments (id, order_id, method, card_number, card_last4, amount, payer_ip, paid_at)
SELECT i, o.id, m.method,
       m.card,
       right(m.card, 4),
       o.total,
       ('203.150.' || seed.h(i, 29) % 256 || '.' || 1 + seed.h(i, 30) % 254)::inet,
       o.created_at + interval '5 minutes'
FROM generate_series(1, 8000) AS i
JOIN orders o ON o.id = i * 6
CROSS JOIN LATERAL (
    SELECT method,
           CASE WHEN method = 'card'
                THEN seed.luhn_complete('4' || lpad((seed.h(i, 31) % 100000000000000)::text, 14, '0'))
           END AS card
    FROM (SELECT (ARRAY['card','promptpay','cod'])[1 + seed.h(i, 28) % 3] AS method) mm
) m;

INSERT INTO sessions (id, customer_id, token, created_at)
SELECT md5('session:' || i)::uuid, 1 + seed.h(i, 32) % 20000, md5('token:' || i),
       timestamptz '2025-12-01 00:00:00+07' + i * interval '1 minute'
FROM generate_series(1, 500) AS i;

INSERT INTO cache_pages (key, body)
SELECT 'page:/products/' || i, repeat('<div>cached</div>', 20)
FROM generate_series(1, 200) AS i;

INSERT INTO audit_raw_logs (id, payload, created_at)
SELECT i,
       jsonb_build_object('event', 'login', 'email', c.email, 'ip', '203.150.1.' || 1 + i % 254,
                          'user_agent', 'Mozilla/5.0'),
       timestamptz '2025-12-01 00:00:00+07' + i * interval '3 minutes'
FROM generate_series(1, 300) AS i
JOIN customers c ON c.id = 1 + seed.h(i, 33) % 20000;

DROP SCHEMA seed CASCADE;
ANALYZE;
