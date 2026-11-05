package scan

import (
	_ "embed"
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"unicode"
)

// Detector names (also used in pgsafe.masking.yaml "detector:" fields).
const (
	DetEmail    = "email"
	DetPhoneTH  = "phone_th"
	DetThaiID   = "thai_id"
	DetTaxID    = "tax_id"
	DetCard     = "credit_card"
	DetIP       = "ip"
	DetNameTH   = "name_th"
	DetNameEN   = "name_en"
	DetAddrTH   = "address_th"
	DetBirth    = "birth_date"
	DetSocial   = "social_id"
	DetPassport = "passport"
	DetBank     = "bank_account"
	DetFreeText = "free_text"
	DetJSON     = "json"
)

var (
	nonDigit   = regexp.MustCompile(`[\s\-.()]`)
	emailRe    = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	emailInRe  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	mobileTHRe = regexp.MustCompile(`^(?:0|\+?66)[689]\d{8}$`)
	landTHRe   = regexp.MustCompile(`^(?:0|\+?66)[2-7]\d{7}$`)
	phoneInRe  = regexp.MustCompile(`(?:\+66|\b0)[689](?:[\s\-]?\d){8}\b`)
	idInRe     = regexp.MustCompile(`\b\d(?:[\s\-]?\d){12}\b`)
	postalRe   = regexp.MustCompile(`(?:^|\D)\d{5}(?:\D|$)`)
	addrWordRe = regexp.MustCompile(`แขวง|เขต|ตำบล|ต\.|อำเภอ|อ\.|จังหวัด|จ\.|หมู่|ซอย|ถนน`)
	titleTHRe  = regexp.MustCompile(`^(?:นาย|นางสาว|นาง|น\.ส\.|ด\.ช\.|ด\.ญ\.|เด็กชาย|เด็กหญิง|คุณ)\s*\S`)
)

//go:embed names_th.txt
var namesTHFile string

// thaiFirstNames is a dictionary of common Thai given names.
var thaiFirstNames = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(namesTHFile, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			m[l] = true
		}
	}
	return m
}()

func digitsOnly(s string) string { return nonDigit.ReplaceAllString(s, "") }

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ThaiIDChecksumOK validates a 13-digit Thai national ID / tax ID.
func ThaiIDChecksumOK(d string) bool {
	if len(d) != 13 || !allDigits(d) {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += int(d[i]-'0') * (13 - i)
	}
	return (11-sum%11)%10 == int(d[12]-'0')
}

// LuhnOK validates a payment card number.
func LuhnOK(d string) bool {
	if len(d) < 13 || len(d) > 19 || !allDigits(d) {
		return false
	}
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// IsThaiID: 13 digits (dashes/spaces allowed) with a valid checksum.
func IsThaiID(v string) bool { return ThaiIDChecksumOK(digitsOnly(v)) }

// IsPhoneTH: Thai mobile (06/08/09 + 8 digits) or landline, local or +66 form.
func IsPhoneTH(v string) bool {
	d := digitsOnly(v)
	if strings.HasPrefix(strings.TrimSpace(v), "+") {
		d = "+" + d
	}
	d = strings.TrimPrefix(d, "+")
	return mobileTHRe.MatchString(d) || landTHRe.MatchString(d)
}

func IsEmail(v string) bool { return emailRe.MatchString(strings.TrimSpace(v)) }

// IsCard: 13–19 digits, Luhn-valid, with a card-network prefix. 13-digit
// values that are valid Thai IDs are not cards.
func IsCard(v string) bool {
	d := digitsOnly(v)
	if !LuhnOK(d) || strings.IndexByte("3456", d[0]) < 0 {
		return false
	}
	return !(len(d) == 13 && ThaiIDChecksumOK(d))
}

func IsIP(v string) bool {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '/'); i > 0 { // inet text may carry a mask
		v = v[:i]
	}
	return net.ParseIP(v) != nil
}

// IsNameTH: starts with a Thai title, or its first word is a known Thai given name.
func IsNameTH(v string) bool {
	v = strings.TrimSpace(v)
	if titleTHRe.MatchString(v) {
		return true
	}
	first := strings.Fields(v)
	return len(first) > 0 && thaiFirstNames[first[0]]
}

// IsAddressTH: Thai administrative words plus a 5-digit postal code.
func IsAddressTH(v string) bool { return addrWordRe.MatchString(v) && postalRe.MatchString(v) }

// ContainsPII reports whether free text embeds an email, Thai phone or Thai ID.
func ContainsPII(v string) bool {
	if emailInRe.MatchString(v) || phoneInRe.MatchString(v) {
		return true
	}
	for _, m := range idInRe.FindAllString(v, -1) {
		if IsThaiID(m) {
			return true
		}
	}
	return false
}

// valueDetectors are tried in order; the first with the best match ratio wins.
var valueDetectors = []struct {
	name string
	fn   func(string) bool
}{
	{DetThaiID, IsThaiID},
	{DetCard, IsCard},
	{DetEmail, IsEmail},
	{DetPhoneTH, IsPhoneTH},
	{DetIP, IsIP},
	{DetAddrTH, IsAddressTH},
	{DetNameTH, IsNameTH},
}

// mostlyLatin reports whether most letters in the samples are Latin.
func mostlyLatin(samples []string) bool {
	latin, thai := 0, 0
	for _, s := range samples {
		for _, r := range s {
			switch {
			case unicode.In(r, unicode.Thai):
				thai++
			case unicode.IsLetter(r) && r < 0x250:
				latin++
			}
		}
	}
	return latin > thai
}

func avgLen(samples []string) float64 {
	if len(samples) == 0 {
		return 0
	}
	n := 0
	for _, s := range samples {
		n += len([]rune(s))
	}
	return float64(n) / float64(len(samples))
}

// jsonObjects decodes samples that are JSON objects.
func jsonObjects(samples []string) []map[string]any {
	var out []map[string]any
	for _, s := range samples {
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}
