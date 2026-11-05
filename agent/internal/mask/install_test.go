package mask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The SQL HMAC is sha256(okey || sha256(ikey || msg)); check the key
// derivation against Go's crypto/hmac.
func TestHMACKeys(t *testing.T) {
	for _, salt := range []string{"0123456789abcdef", string(make([]byte, 100))} {
		ikey, okey := hmacKeys(salt)
		ib, _ := hex.DecodeString(ikey)
		ob, _ := hex.DecodeString(okey)
		inner := sha256.Sum256(append(ib, []byte("msg")...))
		outer := sha256.Sum256(append(ob, inner[:]...))
		m := hmac.New(sha256.New, []byte(salt))
		m.Write([]byte("msg"))
		if hex.EncodeToString(outer[:]) != hex.EncodeToString(m.Sum(nil)) {
			t.Fatalf("salt len %d: manual HMAC != crypto/hmac", len(salt))
		}
	}
}

func TestDictionariesLoad(t *testing.T) {
	for _, d := range dicts {
		rows, err := readDict(d)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) < 20 {
			t.Errorf("%s: only %d entries", d.table, len(rows))
		}
		seen := map[string]bool{}
		for _, r := range rows {
			k := ""
			for _, v := range r[1:] {
				k += "|" + toStringT(v)
			}
			if seen[k] {
				t.Errorf("%s: duplicate entry %s", d.table, k)
			}
			seen[k] = true
		}
	}
}

func toStringT(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if b, ok := v.(bool); ok && b {
		return "true"
	}
	return "false"
}

func TestArrayLiteral(t *testing.T) {
	got := arrayLiteral([]string{"สมชาย", `a"b`, `c\d`, "o'neil"})
	want := `{"สมชาย","a\"b","c\\d","o''neil"}`
	if got != want {
		t.Fatalf("arrayLiteral = %s, want %s", got, want)
	}
}
