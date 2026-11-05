package scan

import (
	"regexp"
	"strings"
)

// nameHint is what a column name or comment suggests.
type nameHint struct {
	detector string
	strong   bool   // strong hints alone give medium confidence; weak ones give low
	part     string // for names: full | first | last
}

var splitRe = regexp.MustCompile(`[^a-z0-9]+|(\d+)`)

// tokens splits a column name into lowercase words: "custEmail2" → [cust email].
func tokens(name string) []string {
	var b strings.Builder
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	var out []string
	for _, t := range splitRe.Split(strings.ToLower(b.String()), -1) {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Exact multi-token names and single tokens, English and transliterated Thai.
var (
	exactNames = map[string]nameHint{
		"first_name": {DetNameTH, true, "first"}, "firstname": {DetNameTH, true, "first"}, "fname": {DetNameTH, true, "first"},
		"given_name": {DetNameTH, true, "first"}, "nick_name": {DetNameTH, true, "first"}, "nickname": {DetNameTH, true, "first"},
		"last_name": {DetNameTH, true, "last"}, "lastname": {DetNameTH, true, "last"}, "lname": {DetNameTH, true, "last"},
		"surname": {DetNameTH, true, "last"}, "family_name": {DetNameTH, true, "last"},
		"full_name": {DetNameTH, true, "full"}, "fullname": {DetNameTH, true, "full"}, "customer_name": {DetNameTH, true, "full"},
		"contact_name": {DetNameTH, true, "full"}, "display_name": {DetNameTH, false, "full"},
		"chue": {DetNameTH, true, "first"}, "chue_len": {DetNameTH, true, "first"}, "namsakul": {DetNameTH, true, "last"},
		"chue_namsakul": {DetNameTH, true, "full"},
		"citizen_id":    {DetThaiID, true, ""}, "national_id": {DetThaiID, true, ""}, "id_card": {DetThaiID, true, ""},
		"idcard": {DetThaiID, true, ""}, "id_card_no": {DetThaiID, true, ""}, "card_id": {DetThaiID, false, ""},
		"personal_id": {DetThaiID, true, ""}, "pid": {DetThaiID, false, ""},
		"tax_id": {DetTaxID, true, ""}, "taxid": {DetTaxID, true, ""}, "tin": {DetTaxID, false, ""},
		"card_number": {DetCard, true, ""}, "card_no": {DetCard, true, ""}, "cc_number": {DetCard, true, ""},
		"credit_card": {DetCard, true, ""}, "pan": {DetCard, false, ""},
		"ip": {DetIP, true, ""}, "ip_address": {DetIP, true, ""}, "ipaddr": {DetIP, true, ""}, "remote_addr": {DetIP, true, ""},
		"line_id": {DetSocial, true, ""}, "lineid": {DetSocial, true, ""}, "line_user_id": {DetSocial, true, ""},
		"facebook": {DetSocial, true, ""}, "facebook_id": {DetSocial, true, ""}, "fb_id": {DetSocial, true, ""},
		"instagram": {DetSocial, true, ""}, "ig": {DetSocial, false, ""}, "tiktok": {DetSocial, true, ""},
		"twitter": {DetSocial, true, ""}, "wechat": {DetSocial, true, ""},
		"bank_account": {DetBank, true, ""}, "account_no": {DetBank, false, ""}, "bank_account_no": {DetBank, true, ""},
		"dob": {DetBirth, true, ""}, "birth_date": {DetBirth, true, ""}, "birthdate": {DetBirth, true, ""},
		"birthday": {DetBirth, true, ""}, "date_of_birth": {DetBirth, true, ""}, "wan_koet": {DetBirth, true, ""},
	}
	tokenNames = map[string]nameHint{
		"email": {DetEmail, true, ""}, "mail": {DetEmail, false, ""},
		"phone": {DetPhoneTH, true, ""}, "mobile": {DetPhoneTH, true, ""}, "tel": {DetPhoneTH, true, ""},
		"telephone": {DetPhoneTH, true, ""}, "msisdn": {DetPhoneTH, true, ""}, "thoorasap": {DetPhoneTH, true, ""},
		"torasap": {DetPhoneTH, true, ""}, "fax": {DetPhoneTH, false, ""},
		"address": {DetAddrTH, true, ""}, "addr": {DetAddrTH, true, ""}, "street": {DetAddrTH, false, ""},
		"thiyu": {DetAddrTH, true, ""}, "thiayu": {DetAddrTH, true, ""},
		"passport": {DetPassport, true, ""},
		"citizen":  {DetThaiID, true, ""},
		"birth":    {DetBirth, true, ""},
		"notes":    {DetFreeText, false, ""}, "note": {DetFreeText, false, ""}, "remark": {DetFreeText, false, ""},
		"remarks": {DetFreeText, false, ""}, "comment": {DetFreeText, false, ""}, "comments": {DetFreeText, false, ""},
		"memo": {DetFreeText, false, ""}, "message": {DetFreeText, false, ""},
	}
	// Thai words in column comments.
	commentHints = []struct {
		word string
		hint nameHint
	}{
		{"บัตรประชาชน", nameHint{DetThaiID, true, ""}},
		{"บัตรประจำตัวประชาชน", nameHint{DetThaiID, true, ""}},
		{"เลขประจำตัวประชาชน", nameHint{DetThaiID, true, ""}},
		{"ผู้เสียภาษี", nameHint{DetTaxID, true, ""}},
		{"อีเมล", nameHint{DetEmail, true, ""}},
		{"เบอร์", nameHint{DetPhoneTH, true, ""}},
		{"โทรศัพท์", nameHint{DetPhoneTH, true, ""}},
		{"มือถือ", nameHint{DetPhoneTH, true, ""}},
		{"นามสกุล", nameHint{DetNameTH, true, "last"}},
		{"ชื่อ-นามสกุล", nameHint{DetNameTH, true, "full"}},
		{"ชื่อ", nameHint{DetNameTH, false, "first"}},
		{"ที่อยู่", nameHint{DetAddrTH, true, ""}},
		{"วันเกิด", nameHint{DetBirth, true, ""}},
		{"ไลน์", nameHint{DetSocial, true, ""}},
		{"บัญชีธนาคาร", nameHint{DetBank, true, ""}},
		{"หนังสือเดินทาง", nameHint{DetPassport, true, ""}},
	}
)

// hintFor returns what the column name (then its comment) suggests, if anything.
func hintFor(column, comment string) (nameHint, bool) {
	lower := strings.ToLower(column)
	if h, ok := exactNames[lower]; ok {
		return h, true
	}
	toks := tokens(column)
	joined := strings.Join(toks, "_")
	if h, ok := exactNames[joined]; ok {
		return h, true
	}
	// "customer_email", "payer_ip", "shipping_address", "mobile_no"
	if len(toks) > 1 {
		if h, ok := exactNames[strings.Join(toks[len(toks)-2:], "_")]; ok {
			return h, true
		}
	}
	for _, t := range toks {
		if h, ok := tokenNames[t]; ok {
			return h, true
		}
	}
	if len(toks) > 0 && toks[len(toks)-1] == "ip" { // payer_ip, client_ip
		return exactNames["ip"], true
	}
	for _, c := range commentHints {
		if strings.Contains(comment, c.word) {
			// "ชื่อ-นามสกุล" beats "นามสกุล" beats "ชื่อ": the list is ordered so
			// that later, more generic words never override a full-name comment.
			if c.word == "นามสกุล" && strings.Contains(comment, "ชื่อ-นามสกุล") {
				continue
			}
			return c.hint, true
		}
	}
	return nameHint{}, false
}
