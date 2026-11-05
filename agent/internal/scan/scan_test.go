package scan

import (
	"strings"
	"testing"
)

func TestThaiID(t *testing.T) {
	valid := []string{"1101700207030", "1-1017-00207-03-0", "1 1017 00207 03 0", "3100600220013"}
	for _, v := range valid {
		if !IsThaiID(v) {
			t.Errorf("IsThaiID(%q) = false", v)
		}
	}
	invalid := []string{"1101700207031", "110170020703", "abcdefghijklm", "", "11017002070300"}
	for _, v := range invalid {
		if IsThaiID(v) {
			t.Errorf("IsThaiID(%q) = true", v)
		}
	}
}

func TestPhoneTH(t *testing.T) {
	for _, v := range []string{"0812345678", "081-234-5678", "+66812345678", "+66 81 234 5678", "0612345678", "0912345678", "021234567"} {
		if !IsPhoneTH(v) {
			t.Errorf("IsPhoneTH(%q) = false", v)
		}
	}
	for _, v := range []string{"0112345678", "12345", "081234567890", "hello"} {
		if IsPhoneTH(v) {
			t.Errorf("IsPhoneTH(%q) = true", v)
		}
	}
}

func TestCard(t *testing.T) {
	for _, v := range []string{"4111111111111111", "4111-1111-1111-1111", "5500 0000 0000 0004", "378282246310005"} {
		if !IsCard(v) {
			t.Errorf("IsCard(%q) = false", v)
		}
	}
	for _, v := range []string{"4111111111111112", "1234567812345670", "1101700207030"} {
		if IsCard(v) {
			t.Errorf("IsCard(%q) = true", v)
		}
	}
}

func TestOtherDetectors(t *testing.T) {
	checks := []struct {
		fn   func(string) bool
		v    string
		want bool
	}{
		{IsEmail, "somchai.j@gmail.com", true},
		{IsEmail, "not an email", false},
		{IsIP, "203.150.1.2", true},
		{IsIP, "2001:db8::1", true},
		{IsIP, "10.0.0.0/8", true},
		{IsIP, "999.1.1.1", false},
		{IsNameTH, "นายสมชาย ใจดี", true},
		{IsNameTH, "นางสาวพิมพ์ชนก แสงทอง", true},
		{IsNameTH, "สมศรี", true},
		{IsNameTH, "เสื้อยืด รุ่น 5", false},
		{IsAddressTH, "12/3 ถนนสุขุมวิท แขวงคลองเตย เขตคลองเตย กรุงเทพมหานคร 10110", true},
		{IsAddressTH, "99 หมู่ 2 ตำบลสุเทพ อำเภอเมืองเชียงใหม่ จังหวัดเชียงใหม่ 50200", true},
		{IsAddressTH, "ตำบลสุเทพ ไม่มีรหัส", false},
		{ContainsPII, "ลูกค้าขอให้โทรกลับที่ 0812345678", true},
		{ContainsPII, "send to a.b@example.com please", true},
		{ContainsPII, "เลขบัตร 1-1017-00207-03-0", true},
		{ContainsPII, "ลูกค้าประจำ", false},
	}
	for _, c := range checks {
		if got := c.fn(c.v); got != c.want {
			t.Errorf("detector(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestHints(t *testing.T) {
	tests := []struct {
		col, comment, want string
	}{
		{"email", "", DetEmail},
		{"customer_email", "", DetEmail},
		{"custEmail", "", DetEmail},
		{"mobile_no", "", DetPhoneTH},
		{"citizen_id", "", DetThaiID},
		{"tax_id", "", DetTaxID},
		{"first_name", "", DetNameTH},
		{"namsakul", "", DetNameTH},
		{"thiyu", "", DetAddrTH},
		{"shipping_address", "", DetAddrTH},
		{"payer_ip", "", DetIP},
		{"line_id", "", DetSocial},
		{"dob", "", DetBirth},
		{"col_x", "เลขประจำตัวประชาชน", DetThaiID},
		{"col_y", "ชื่อ-นามสกุลลูกค้า", DetNameTH},
		{"col_z", "เบอร์โทร", DetPhoneTH},
	}
	for _, tt := range tests {
		h, ok := hintFor(tt.col, tt.comment)
		if !ok || h.detector != tt.want {
			t.Errorf("hintFor(%q, %q) = %+v %v, want %s", tt.col, tt.comment, h, ok, tt.want)
		}
	}
	for _, col := range []string{"tier", "created_at", "status", "province", "card_last4", "order_id", "line_items"} {
		if h, ok := hintFor(col, ""); ok {
			t.Errorf("hintFor(%q) = %+v, want no hint", col, h)
		}
	}
	if h, _ := hintFor("col_y", "ชื่อ-นามสกุลลูกค้า"); h.part != "full" {
		t.Errorf("full-name comment part = %q", h.part)
	}
}

func repeat(v string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name     string
		col      Column
		det      string
		conf     string
		strategy string
	}{
		{"email by name+values", Column{Name: "email", Type: "text", Samples: repeat("a.b@gmail.com", 10)}, DetEmail, High, "fake_email"},
		{"email by values only", Column{Name: "contact", Type: "text", Samples: repeat("a.b@gmail.com", 10)}, DetEmail, High, "fake_email"},
		{"thai id", Column{Name: "citizen_id", Type: "character(13)", Samples: repeat("1101700207030", 10)}, DetThaiID, High, "fake_thai_id"},
		{"name only, empty table", Column{Name: "last_name", Type: "text"}, DetNameTH, Medium, "fake_name_th"},
		{"english names", Column{Name: "first_name", Type: "text", Samples: repeat("John", 10)}, DetNameEN, Medium, "fake_name_en"},
		{"inet", Column{Name: "x", Type: "inet"}, DetIP, High, "fake_ip"},
		{"birth date", Column{Name: "birth_date", Type: "date"}, DetBirth, High, "date_shift"},
		{"line id by name", Column{Name: "line_id", Type: "text", Samples: repeat("@somchai99", 10)}, DetSocial, Medium, "hash"},
		{"free text", Column{Name: "notes", Type: "text", Samples: append(repeat("ลูกค้าขอให้โทรกลับที่ 0812345678 ด่วนมากครับ", 3), repeat("ลูกค้าประจำ ชอบสั่งชาไทยทุกสัปดาห์ครับผม", 7)...)}, DetFreeText, High, "redact"},
		{"json keys", Column{Name: "payload", Type: "jsonb", Samples: repeat(`{"event":"login","email":"a@b.co","ip":"1.2.3.4"}`, 5)}, DetJSON, High, "json_mask"},
	}
	for _, tt := range tests {
		f, ok := Classify(tt.col)
		if !ok {
			t.Errorf("%s: not classified", tt.name)
			continue
		}
		if f.Detector != tt.det || f.Confidence != tt.conf || f.Strategy != tt.strategy {
			t.Errorf("%s: got %s/%s/%s, want %s/%s/%s (%s)", tt.name, f.Detector, f.Confidence, f.Strategy, tt.det, tt.conf, tt.strategy, f.Reason)
		}
	}

	notPII := []Column{
		{Name: "tier", Type: "text", Samples: repeat("gold", 10)},
		{Name: "name", Type: "text", Samples: repeat("เสื้อยืด รุ่น 5", 10)},
		{Name: "status", Type: "text", Samples: repeat("shipped", 10)},
		{Name: "created_at", Type: "timestamp with time zone"},
		{Name: "preferences", Type: "jsonb", Samples: repeat(`{"newsletter":true,"lang":"th"}`, 10)},
		{Name: "notes", Type: "text", Samples: repeat("ลูกค้าประจำ ชอบสั่งชาไทยทุกสัปดาห์ครับผม", 10)},
	}
	for _, c := range notPII {
		if f, ok := Classify(c); ok && Blocking(f.Confidence) {
			t.Errorf("%s flagged as %s/%s (%s)", c.Name, f.Detector, f.Confidence, f.Reason)
		}
	}
}

func TestJSONKeysStrategies(t *testing.T) {
	f, ok := Classify(Column{Name: "payload", Type: "jsonb", Samples: repeat(`{"email":"a@b.co","phone":"0812345678","lang":"th"}`, 5)})
	if !ok || f.JSONKeys["email"] != "fake_email" || f.JSONKeys["phone"] != "fake_phone_th" || f.JSONKeys["lang"] != "" {
		t.Fatalf("json keys = %v", f.JSONKeys)
	}
	if !strings.Contains(f.Reason, "email") {
		t.Fatalf("reason = %s", f.Reason)
	}
}
