//go:build e2e

package e2e

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var sources = []struct {
	major int
	url   string
}{
	{14, env("PG14_DATABASE_URL", "postgres://pgsafe:pgsafe@localhost:5414/shop?sslmode=disable")},
	{16, env("PG16_DATABASE_URL", "postgres://pgsafe:pgsafe@localhost:5416/shop?sslmode=disable")},
	{18, env("PG18_DATABASE_URL", "postgres://pgsafe:pgsafe@localhost:5418/shop?sslmode=disable")},
}

var wantRows = map[string]int64{
	"products":       1000,
	"customers":      20000,
	"orders":         50000,
	"order_items":    20000,
	"payments":       8000,
	"sessions":       500,
	"cache_pages":    200,
	"audit_raw_logs": 300,
}

func connect(t *testing.T, url string) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect (did you run `make dev-up`?): %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func TestSeedSources(t *testing.T) {
	for _, src := range sources {
		t.Run("pg"+strconv.Itoa(src.major), func(t *testing.T) {
			ctx := context.Background()
			conn := connect(t, src.url)

			var versionNum int
			if err := conn.QueryRow(ctx, "select current_setting('server_version_num')::int").Scan(&versionNum); err != nil {
				t.Fatal(err)
			}
			if got := versionNum / 10000; got != src.major {
				t.Fatalf("server major = %d, want %d", got, src.major)
			}

			var total int64
			for table, want := range wantRows {
				var got int64
				if err := conn.QueryRow(ctx, "select count(*) from "+pgx.Identifier{"public", table}.Sanitize()).Scan(&got); err != nil {
					t.Fatalf("%s: %v", table, err)
				}
				if got != want {
					t.Errorf("%s rows = %d, want %d", table, got, want)
				}
				total += got
			}
			if total != 100000 {
				t.Errorf("total rows = %d, want 100000", total)
			}

			var seedSchema bool
			if err := conn.QueryRow(ctx, "select exists(select 1 from pg_namespace where nspname = 'seed')").Scan(&seedSchema); err != nil {
				t.Fatal(err)
			}
			if seedSchema {
				t.Error("helper schema 'seed' should be dropped after seeding")
			}

			// Every value the Phase 2 detectors rely on must be valid in the seed.
			checks := []struct{ name, sql string }{
				{"citizen_id checksum", `
					select count(*) from customers c
					where right(c.citizen_id, 1)::int <> (11 - (
						select sum(substr(c.citizen_id, k, 1)::int * (14 - k)) from generate_series(1, 12) k
					) % 11) % 10`},
				{"phone format", `select count(*) from customers where phone !~ '^(0|\+66)[689][0-9]{8}$'`},
				{"thai name title", `select count(*) from customers where full_name !~ '^(นาย|นาง|นางสาว)'`},
				{"address has postal code", `select count(*) from customers where address !~ '[0-9]{5}$'`},
				{"orders.customer_email matches", `
					select count(*) from orders o join customers c on c.id = o.customer_id
					where o.customer_email <> c.email`},
				{"card luhn", `
					select count(*) from payments p
					where card_number is not null and (
						select sum(case when (16 - k) % 2 = 1
						                then (substr(p.card_number, k, 1)::int * 2) / 10 + (substr(p.card_number, k, 1)::int * 2) % 10
						                else substr(p.card_number, k, 1)::int end)
						from generate_series(1, 16) k) % 10 <> 0`},
			}
			for _, c := range checks {
				var bad int64
				if err := conn.QueryRow(ctx, c.sql).Scan(&bad); err != nil {
					t.Fatalf("%s: %v", c.name, err)
				}
				if bad != 0 {
					t.Errorf("%s: %d bad rows", c.name, bad)
				}
			}

			var cards int64
			if err := conn.QueryRow(ctx, "select count(*) from payments where card_number is not null").Scan(&cards); err != nil {
				t.Fatal(err)
			}
			if cards == 0 {
				t.Error("expected some card payments")
			}
		})
	}
}

// The seed must be byte-for-byte identical across versions (golden tests depend on it).
func TestSeedDeterministicAcrossVersions(t *testing.T) {
	const q = `select md5(string_agg(c::text, '|' order by id)) from customers c`
	var first string
	for i, src := range sources {
		conn := connect(t, src.url)
		var sum string
		if err := conn.QueryRow(context.Background(), q).Scan(&sum); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = sum
		} else if sum != first {
			t.Errorf("pg%d customers hash %s differs from pg%d %s", src.major, sum, sources[0].major, first)
		}
	}
}

func TestEmptyTargets(t *testing.T) {
	for name, url := range map[string]string{
		"staging": env("STAGING_DATABASE_URL", "postgres://pgsafe:pgsafe@localhost:5433/shop_staging?sslmode=disable"),
		"meta":    env("META_DATABASE_URL", "postgres://pgsafe:pgsafe@localhost:5434/pgsafe_meta?sslmode=disable"),
	} {
		t.Run(name, func(t *testing.T) {
			conn := connect(t, url)
			if err := conn.Ping(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMinioBucket(t *testing.T) {
	u, err := url.Parse(env("S3_ENDPOINT", "http://localhost:9000"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := minio.New(u.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(env("PGSAFE_DEV_MINIO_USER", "pgsafeminio"), env("PGSAFE_DEV_MINIO_PASSWORD", "pgsafeminio"), ""),
		Secure: u.Scheme == "https",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bucket := env("PGSAFE_DEV_BUCKET", "pgsafe-dev")
	ok, err := client.BucketExists(ctx, bucket)
	if err != nil {
		t.Fatalf("minio: %v", err)
	}
	if !ok {
		t.Fatalf("bucket %q does not exist", bucket)
	}
}
