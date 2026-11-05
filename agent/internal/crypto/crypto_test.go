package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptStreamWithHash(t *testing.T) {
	dir := t.TempDir()
	pub, key := filepath.Join(dir, "k.pub"), filepath.Join(dir, "k.key")
	if _, err := GenerateKey(pub, key); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKey(pub, key); err == nil {
		t.Fatal("GenerateKey must not overwrite existing keys")
	}
	rs, err := LoadRecipients(pub)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := LoadIdentities(key)
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, 3<<20+123) // > age's 64KiB chunk size, not chunk aligned
	rand.Read(plain)

	var stored bytes.Buffer
	h := NewHasher()
	w, err := Encrypt(io.MultiWriter(&stored, h), rs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(w, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(stored.Bytes())
	if h.Sum() != hex.EncodeToString(want[:]) || h.Size() != int64(stored.Len()) {
		t.Fatal("hasher does not match stored bytes")
	}

	r, err := Decrypt(bytes.NewReader(stored.Bytes()), ids)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("roundtrip mismatch")
	}

	// Truncated ciphertext must fail, never silently return a short plaintext.
	half := stored.Bytes()[:stored.Len()/2]
	r, err = Decrypt(bytes.NewReader(half), ids)
	if err == nil {
		_, err = io.ReadAll(r)
	}
	if err == nil {
		t.Fatal("truncated ciphertext decrypted without error")
	}
}
