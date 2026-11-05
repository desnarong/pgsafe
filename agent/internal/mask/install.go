package mask

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed sql/*.sql dict/*.csv
var assets embed.FS

// Schema is the helper schema created in the scratch database.
const Schema = "pgsafe_mask"

// hmacKeys returns the HMAC-SHA256 inner and outer padded keys for salt
// (RFC 2104). They are embedded in the scratch-only functions so no salt-derived
// value is ever passed per row.
func hmacKeys(salt string) (ikey, okey string) {
	key := []byte(salt)
	if len(key) > 64 {
		s := sha256.Sum256(key)
		key = s[:]
	}
	block := make([]byte, 64)
	copy(block, key)
	in, out := make([]byte, 64), make([]byte, 64)
	for i, b := range block {
		in[i], out[i] = b^0x36, b^0x5c
	}
	return hex.EncodeToString(in), hex.EncodeToString(out)
}

type dict struct {
	table string
	file  string
	cols  []string
}

var dicts = []dict{
	{"th_first", "dict/th_first.csv", []string{"i", "name", "gender"}},
	{"th_last", "dict/th_last.csv", []string{"i", "name"}},
	{"en_first", "dict/en_first.csv", []string{"i", "name"}},
	{"en_last", "dict/en_last.csv", []string{"i", "name"}},
	{"th_areas", "dict/th_areas.csv", []string{"i", "subdistrict", "district", "province", "postal", "bkk"}},
}

func readDict(d dict) ([][]any, error) {
	f, err := assets.Open(d.file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = len(d.cols) - 1
	recs, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", d.file, err)
	}
	rows := make([][]any, len(recs))
	for i, rec := range recs {
		row := []any{i + 1}
		for _, v := range rec {
			row = append(row, strings.TrimSpace(v))
		}
		if d.table == "th_areas" {
			row[5] = row[5] == "true"
		}
		rows[i] = row
	}
	return rows, nil
}

func column(rows [][]any, i int) []string {
	out := make([]string, len(rows))
	for j, r := range rows {
		out[j] = toText(r[i])
	}
	return out
}

func toText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(x)
	}
}

// Install creates the pgsafe_mask schema and the masking functions keyed by
// salt, with the dictionaries embedded as constant arrays (fast, no lookups).
func Install(ctx context.Context, conn *pgx.Conn, salt string) error {
	schema, err := assets.ReadFile("sql/schema.sql")
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+Schema+" CASCADE"); err != nil {
		return fmt.Errorf("drop old %s: %w", Schema, err)
	}
	if _, err := conn.Exec(ctx, string(schema)); err != nil {
		return fmt.Errorf("create %s: %w", Schema, err)
	}
	data := map[string][][]any{}
	for _, d := range dicts {
		rows, err := readDict(d)
		if err != nil {
			return err
		}
		data[d.table] = rows
	}
	areas := make([]string, len(data["th_areas"]))
	for i, r := range data["th_areas"] {
		sub, dist, prov, postal, bkk := toText(r[1]), toText(r[2]), toText(r[3]), toText(r[4]), r[5].(bool)
		if bkk {
			areas[i] = "แขวง" + sub + " เขต" + dist + " " + prov + " " + postal
		} else {
			areas[i] = "ตำบล" + sub + " อำเภอ" + dist + " จังหวัด" + prov + " " + postal
		}
	}
	fns, err := assets.ReadFile("sql/functions.sql")
	if err != nil {
		return err
	}
	ikey, okey := hmacKeys(salt)
	fkey := sha256.Sum256([]byte("pgsafe-fpe:" + salt))
	n := func(t string) string { return fmt.Sprint(len(data[t])) }
	body := strings.NewReplacer(
		"{{IKEY}}", ikey, "{{OKEY}}", okey, "{{FKEY}}", hex.EncodeToString(fkey[:]),
		"{{N_TH_FIRST}}", n("th_first"), "{{N_TH_LAST}}", n("th_last"),
		"{{N_EN_FIRST}}", n("en_first"), "{{N_EN_LAST}}", n("en_last"), "{{N_TH_AREAS}}", n("th_areas"),
		"{{A_TH_FIRST}}", arrayLiteral(column(data["th_first"], 1)),
		"{{A_TH_GENDER}}", arrayLiteral(column(data["th_first"], 2)),
		"{{A_TH_LAST}}", arrayLiteral(column(data["th_last"], 1)),
		"{{A_EN_FIRST}}", arrayLiteral(column(data["en_first"], 1)),
		"{{A_EN_LAST}}", arrayLiteral(column(data["en_last"], 1)),
		"{{A_TH_AREAS}}", arrayLiteral(areas),
	).Replace(string(fns))
	if _, err := conn.Exec(ctx, body); err != nil {
		// The error may quote the function body (which holds the keys): keep only the message.
		return fmt.Errorf("create masking functions: %s", firstLine(err.Error()))
	}
	return nil
}

// Uninstall drops the helper schema (and with it the salt-derived keys).
func Uninstall(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+Schema+" CASCADE")
	return err
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
