-- Helper schema used only while seeding; dropped at the end of 03_data.sql.
-- Every generated value is derived from a hash of the row number, so the seed
-- is identical on every run and every PostgreSQL version (needed for golden tests).

CREATE SCHEMA seed;

-- h(i, salt): deterministic non-negative bigint (60 bits) from md5.
CREATE FUNCTION seed.h(i integer, salt integer) RETURNS bigint
LANGUAGE sql IMMUTABLE AS $$
    SELECT ('x' || substr(md5(i::text || ':' || salt::text), 1, 15))::bit(60)::bigint
$$;

-- Thai national ID: 12 digits + checksum digit = (11 - Σ d_k·(14-k) mod 11) mod 10.
CREATE FUNCTION seed.thai_id_complete(p text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT p || ((11 - sum(substr(p, k, 1)::int * (14 - k)) % 11) % 10)::text
    FROM generate_series(1, 12) AS k
$$;

-- Luhn: append the check digit to a numeric payload.
CREATE FUNCTION seed.luhn_complete(p text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT p || ((10 - sum(v) % 10) % 10)::text
    FROM (
        SELECT CASE WHEN (length(p) - k) % 2 = 0
                    THEN (substr(p, k, 1)::int * 2) / 10 + (substr(p, k, 1)::int * 2) % 10
                    ELSE substr(p, k, 1)::int END AS v
        FROM generate_series(1, length(p)) AS k
    ) t
$$;

CREATE TABLE seed.first_names (n serial, th text, en text, gender char(1));
INSERT INTO seed.first_names (th, en, gender) VALUES
    ('สมชาย','somchai','M'), ('สมศักดิ์','somsak','M'), ('ประเสริฐ','prasert','M'),
    ('วิชัย','wichai','M'), ('สุรชัย','surachai','M'), ('ธนากร','thanakorn','M'),
    ('ณัฐพล','nattapon','M'), ('กิตติพงษ์','kittipong','M'), ('อนุชา','anucha','M'),
    ('พงศกร','pongsakorn','M'),
    ('สมศรี','somsri','F'), ('สุดารัตน์','sudarat','F'), ('กมลวรรณ','kamonwan','F'),
    ('ปิยะนุช','piyanuch','F'), ('วรรณา','wanna','F'), ('นภัสสร','napatsorn','F'),
    ('ศิริพร','siriporn','F'), ('อรอุมา','onuma','F'), ('จิราพร','jiraporn','F'),
    ('พิมพ์ชนก','pimchanok','F');

CREATE TABLE seed.last_names (n serial, th text, en text);
INSERT INTO seed.last_names (th, en) VALUES
    ('สุขใจ','sukjai'), ('ศรีสวัสดิ์','srisawat'), ('วงศ์ใหญ่','wongyai'),
    ('แสงทอง','saengthong'), ('บุญมา','boonma'), ('ทองดี','thongdee'),
    ('รัตนพันธ์','rattanapan'), ('เจริญสุข','charoensuk'), ('พรหมมา','promma'),
    ('กิจเจริญ','kitcharoen'), ('ใจดี','jaidee'), ('มั่นคง','mankong');

-- Real subdistrict/district/province/postal-code tuples.
CREATE TABLE seed.areas (n serial, subdistrict text, district text, province text, postal char(5), bkk boolean);
INSERT INTO seed.areas (subdistrict, district, province, postal, bkk) VALUES
    ('คลองเตย','คลองเตย','กรุงเทพมหานคร','10110',true),
    ('ลุมพินี','ปทุมวัน','กรุงเทพมหานคร','10330',true),
    ('สีลม','บางรัก','กรุงเทพมหานคร','10500',true),
    ('จตุจักร','จตุจักร','กรุงเทพมหานคร','10900',true),
    ('ห้วยขวาง','ห้วยขวาง','กรุงเทพมหานคร','10310',true),
    ('สามเสนใน','พญาไท','กรุงเทพมหานคร','10400',true),
    ('บางนาเหนือ','บางนา','กรุงเทพมหานคร','10260',true),
    ('ศรีภูมิ','เมืองเชียงใหม่','เชียงใหม่','50200',false),
    ('สุเทพ','เมืองเชียงใหม่','เชียงใหม่','50200',false),
    ('ในเมือง','เมืองขอนแก่น','ขอนแก่น','40000',false),
    ('หาดใหญ่','หาดใหญ่','สงขลา','90110',false),
    ('ตลาดใหญ่','เมืองภูเก็ต','ภูเก็ต','83000',false),
    ('ในเมือง','เมืองนครราชสีมา','นครราชสีมา','30000',false),
    ('บางพลีใหญ่','บางพลี','สมุทรปราการ','10540',false),
    ('บางกระสอ','เมืองนนทบุรี','นนทบุรี','11000',false),
    ('หนองปรือ','บางละมุง','ชลบุรี','20150',false);

CREATE TABLE seed.streets (n serial, name text);
INSERT INTO seed.streets (name) VALUES
    ('สุขุมวิท'), ('พหลโยธิน'), ('รัชดาภิเษก'), ('เพชรบุรี'), ('ลาดพร้าว'),
    ('มิตรภาพ'), ('นิมมานเหมินท์'), ('เพชรเกษม'), ('บางนา-ตราด'), ('ศรีนครินทร์');

CREATE TABLE seed.product_words (n serial, name text);
INSERT INTO seed.product_words (name) VALUES
    ('เสื้อยืด'), ('กางเกงยีนส์'), ('รองเท้าผ้าใบ'), ('กระเป๋าเป้'), ('หูฟังไร้สาย'),
    ('แก้วเก็บความเย็น'), ('หม้อหุงข้าว'), ('พัดลมตั้งโต๊ะ'), ('ครีมกันแดด'), ('ชาไทย');
