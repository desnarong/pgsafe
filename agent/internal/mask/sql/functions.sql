-- pgsafe masking functions, installed into the scratch database only and
-- dropped (DROP SCHEMA pgsafe_mask CASCADE) before the masked dump is taken.
-- {{IKEY}} / {{OKEY}} are the HMAC inner/outer keys derived from masking.salt;
-- {{N_*}} are dictionary sizes. All functions are deterministic for a salt.

-- HMAC-SHA256(salt, msg)
CREATE FUNCTION pgsafe_mask.hmac(msg text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT sha256('\x{{OKEY}}'::bytea || sha256('\x{{IKEY}}'::bytea || convert_to(msg, 'UTF8')))
$$;

-- 60-bit non-negative integer from HMAC(tag, value), for picking/derivation.
CREATE FUNCTION pgsafe_mask.h(tag text, v text) RETURNS bigint
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT ('x' || substr(encode(pgsafe_mask.hmac(tag || chr(31) || v), 'hex'), 1, 15))::bit(60)::bigint
$$;

CREATE FUNCTION pgsafe_mask.hash(v text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT encode(pgsafe_mask.hmac('hash' || chr(31) || v), 'hex')
$$;

-- Format-preserving permutation of a digit string (unbalanced Feistel network
-- as in FF1, 8 rounds). The round function is SHA-256 keyed with a secret
-- derived from the salt ({{FKEY}}); inputs are fixed-format so prefix-keying
-- is a sound PRF here. It is a bijection on strings of the same length, so
-- distinct inputs give distinct outputs and unique constraints survive masking.
CREATE FUNCTION pgsafe_mask.fpe(d text, tag text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    n int := length(d);
    u int := n / 2;
    v int := n - u;
    pu bigint;
    pv bigint;
    a bigint;
    b bigint;
    c bigint;
    k bytea;
BEGIN
    IF n < 2 OR n > 30 OR d !~ '^[0-9]+$' THEN
        RETURN d;
    END IF;
    pu := (10::numeric ^ u)::bigint;
    pv := (10::numeric ^ v)::bigint;
    k := '\x{{FKEY}}'::bytea || convert_to(tag || ':' || n || ':', 'UTF8');
    a := substr(d, 1, u)::bigint;
    b := substr(d, u + 1)::bigint;
    FOR i IN 0..7 LOOP
        -- even rounds: A has u digits and B has v; odd rounds: the reverse
        c := ('x' || substr(encode(sha256(k || convert_to(i || ':' || b, 'UTF8')), 'hex'), 1, 15))::bit(60)::bigint;
        IF i % 2 = 0 THEN
            c := (a + c % pu) % pu;
        ELSE
            c := (a + c % pv) % pv;
        END IF;
        a := b;
        b := c;
    END LOOP;
    RETURN lpad(a::text, u, '0') || lpad(b::text, v, '0');
END $$;

-- Thai national ID check digit for 12 digits.
CREATE FUNCTION pgsafe_mask.thai_id_check(p text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT ((11 - sum(substr(p, k, 1)::int * (14 - k)) % 11) % 10)::text
    FROM generate_series(1, 12) AS k
$$;

-- Luhn check digit for a payload.
CREATE FUNCTION pgsafe_mask.luhn_check(p text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT ((10 - sum(CASE WHEN (length(p) - k) % 2 = 0
                           THEN (substr(p, k, 1)::int * 2) / 10 + (substr(p, k, 1)::int * 2) % 10
                           ELSE substr(p, k, 1)::int END) % 10) % 10)::text
    FROM generate_series(1, length(p)) AS k
$$;

CREATE FUNCTION pgsafe_mask.fake_email(v text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT 'user_' || substr(pgsafe_mask.hash(lower(btrim(v))), 1, 16) || '@example.test'
$$;

-- Keeps the first digit (region code) and recomputes the checksum; the 11
-- digits in between are permuted, so the result is unique and valid.
CREATE FUNCTION pgsafe_mask.fake_thai_id(v text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    d text := regexp_replace(v, '\D', '', 'g');
    p text;
    out text;
BEGIN
    IF length(d) = 13 THEN
        p := substr(d, 1, 1) || pgsafe_mask.fpe(substr(d, 2, 11), 'thai_id');
    ELSE
        p := (1 + pgsafe_mask.h('thai_id_fb', v) % 8)::text || lpad((pgsafe_mask.h('thai_id_fb2', v) % 100000000000)::text, 11, '0');
    END IF;
    out := p || pgsafe_mask.thai_id_check(p);
    IF v ~ '^\d-\d{4}-\d{5}-\d{2}-\d$' THEN
        out := substr(out, 1, 1) || '-' || substr(out, 2, 4) || '-' || substr(out, 6, 5) || '-' || substr(out, 11, 2) || '-' || substr(out, 13, 1);
    END IF;
    RETURN out;
END $$;

-- Thai phone: keeps the 2-digit prefix (06/08/09, 02…) and the +66 form,
-- permutes the rest.
CREATE FUNCTION pgsafe_mask.fake_phone_th(v text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    d text := regexp_replace(v, '\D', '', 'g');
    intl boolean := false;
    nat text;
    out text;
BEGIN
    IF d LIKE '66%' AND length(d) IN (10, 11) THEN
        intl := true;
        nat := '0' || substr(d, 3);
    ELSE
        nat := d;
    END IF;
    IF nat ~ '^0[689]\d{8}$' OR nat ~ '^0[2-7]\d{7}$' THEN
        out := substr(nat, 1, 2) || pgsafe_mask.fpe(substr(nat, 3), 'phone');
    ELSE
        out := '08' || lpad((pgsafe_mask.h('phone_fb', v) % 100000000)::text, 8, '0');
    END IF;
    IF intl THEN
        out := '+66' || substr(out, 2);
    END IF;
    RETURN out;
END $$;

-- Payment card: keeps the network digit and length, permutes the middle,
-- recomputes the Luhn digit.
CREATE FUNCTION pgsafe_mask.fake_card(v text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    d text := regexp_replace(v, '\D', '', 'g');
    p text;
BEGIN
    IF length(d) BETWEEN 13 AND 19 THEN
        p := substr(d, 1, 1) || pgsafe_mask.fpe(substr(d, 2, length(d) - 2), 'card');
    ELSE
        p := '4' || lpad((pgsafe_mask.h('card_fb', v) % 100000000000000)::text, 14, '0');
    END IF;
    RETURN p || pgsafe_mask.luhn_check(p);
END $$;

-- IPv4 → 10.0.0.0/8, IPv6 → fd00::/8.
CREATE FUNCTION pgsafe_mask.fake_ip(v text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    hx text := encode(pgsafe_mask.hmac('ip' || chr(31) || v), 'hex');
BEGIN
    IF position(':' IN v) > 0 THEN
        RETURN 'fd' || substr(hx, 1, 2) || ':' || substr(hx, 3, 4) || ':' || substr(hx, 7, 4) || ':' || substr(hx, 11, 4)
            || ':' || substr(hx, 15, 4) || ':' || substr(hx, 19, 4) || ':' || substr(hx, 23, 4) || ':' || substr(hx, 27, 4);
    END IF;
    RETURN '10.' || ('x' || substr(hx, 1, 2))::bit(8)::int || '.' || ('x' || substr(hx, 3, 2))::bit(8)::int
        || '.' || (1 + ('x' || substr(hx, 5, 2))::bit(8)::int % 254);
END $$;

-- 1-based index in [1, n] from 3 bytes of a digest at offset off.
CREATE FUNCTION pgsafe_mask.pick(d bytea, off int, n int) RETURNS int
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT 1 + ((get_byte(d, off) << 16) | (get_byte(d, off + 1) << 8) | get_byte(d, off + 2)) % n
$$;

-- Names and addresses take every choice from a single HMAC of the value.
CREATE FUNCTION pgsafe_mask.name_th_d(d bytea, part text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    fi int := pgsafe_mask.pick(d, 0, {{N_TH_FIRST}});
    f text := ('{{A_TH_FIRST}}'::text[])[fi];
    l text := ('{{A_TH_LAST}}'::text[])[pgsafe_mask.pick(d, 3, {{N_TH_LAST}})];
BEGIN
    IF part = 'first' THEN RETURN f; END IF;
    IF part = 'last' THEN RETURN l; END IF;
    IF ('{{A_TH_GENDER}}'::text[])[fi] = 'M' THEN RETURN 'นาย' || f || ' ' || l; END IF;
    IF get_byte(d, 6) % 2 = 0 THEN RETURN 'นาง' || f || ' ' || l; END IF;
    RETURN 'นางสาว' || f || ' ' || l;
END $$;

CREATE FUNCTION pgsafe_mask.fake_name_th(v text, part text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT pgsafe_mask.name_th_d(pgsafe_mask.hmac('name' || chr(31) || v), part)
$$;

CREATE FUNCTION pgsafe_mask.name_en_d(d bytea, part text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    f text := ('{{A_EN_FIRST}}'::text[])[pgsafe_mask.pick(d, 0, {{N_EN_FIRST}})];
    l text := ('{{A_EN_LAST}}'::text[])[pgsafe_mask.pick(d, 3, {{N_EN_LAST}})];
BEGIN
    IF part = 'first' THEN RETURN f; END IF;
    IF part = 'last' THEN RETURN l; END IF;
    RETURN f || ' ' || l;
END $$;

CREATE FUNCTION pgsafe_mask.fake_name_en(v text, part text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT pgsafe_mask.name_en_d(pgsafe_mask.hmac('name' || chr(31) || v), part)
$$;

-- A real subdistrict/district/province/postal code with a made-up house number.
-- Each {{A_TH_AREAS}} element is "แขวงX เขตY กรุงเทพมหานคร 10110" or "ตำบลX อำเภอY จังหวัดZ 50200".
CREATE FUNCTION pgsafe_mask.address_th_d(d bytea) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT 'เลขที่ ' || pgsafe_mask.pick(d, 0, 499) || ' หมู่ ' || pgsafe_mask.pick(d, 3, 15) || ' '
        || ('{{A_TH_AREAS}}'::text[])[pgsafe_mask.pick(d, 6, {{N_TH_AREAS}})]
$$;

CREATE FUNCTION pgsafe_mask.fake_address_th(v text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT pgsafe_mask.address_th_d(pgsafe_mask.hmac('addr' || chr(31) || v))
$$;

-- Shift by a stable number of days in [-max_days, max_days], keyed by the row.
CREATE FUNCTION pgsafe_mask.shift_days(k text, max_days int) RETURNS int
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT (pgsafe_mask.h('date_shift', k) % (2 * max_days + 1))::int - max_days
$$;

-- Multiplier in [1 - pct%, 1 + pct%], keyed by the row.
CREATE FUNCTION pgsafe_mask.noise_factor(k text, pct numeric) RETURNS numeric
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT 1 + ((pgsafe_mask.h('noise', k) % 2001) - 1000)::numeric / 1000 * pct / 100
$$;

-- Replace emails and long digit runs (phones, IDs, cards, accounts) in free text.
CREATE FUNCTION pgsafe_mask.redact(v text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT regexp_replace(
             regexp_replace(v, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[REDACTED]', 'g'),
             '\+?\d[\d \-]{7,}\d', '[REDACTED]', 'g')
$$;

-- Apply a strategy to a text value (used inside json_mask).
CREATE FUNCTION pgsafe_mask.apply(strategy text, v text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE strategy
        WHEN 'null'            THEN NULL
        WHEN 'hash'            THEN pgsafe_mask.hash(v)
        WHEN 'redact'          THEN pgsafe_mask.redact(v)
        WHEN 'fake_email'      THEN pgsafe_mask.fake_email(v)
        WHEN 'fake_phone_th'   THEN pgsafe_mask.fake_phone_th(v)
        WHEN 'fake_thai_id'    THEN pgsafe_mask.fake_thai_id(v)
        WHEN 'fake_card'       THEN pgsafe_mask.fake_card(v)
        WHEN 'fake_name_th'    THEN pgsafe_mask.fake_name_th(v, 'full')
        WHEN 'fake_name_en'    THEN pgsafe_mask.fake_name_en(v, 'full')
        WHEN 'fake_address_th' THEN pgsafe_mask.fake_address_th(v)
    END
$$;

-- Mask top-level string values of a JSON object; keys: {"email": "fake_email", ...}
CREATE FUNCTION pgsafe_mask.json_mask(v jsonb, keys jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    k text;
    s text;
BEGIN
    IF jsonb_typeof(v) <> 'object' THEN
        RETURN v;
    END IF;
    FOR k, s IN SELECT * FROM jsonb_each_text(keys) LOOP
        IF v ? k AND jsonb_typeof(v -> k) IN ('string', 'number') THEN
            v := jsonb_set(v, ARRAY[k], coalesce(to_jsonb(pgsafe_mask.apply(s, v ->> k)), 'null'::jsonb));
        END IF;
    END LOOP;
    RETURN v;
END $$;
