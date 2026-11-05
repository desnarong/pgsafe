package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

// LoadRecipients reads age public keys (one per line, # comments allowed).
func LoadRecipients(path string) ([]age.Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open recipients file: %w", err)
	}
	defer f.Close()
	rs, err := age.ParseRecipients(f)
	if err != nil {
		return nil, fmt.Errorf("parse recipients file %s: %w", path, err)
	}
	return rs, nil
}

// LoadIdentities reads age private keys (as written by age-keygen).
func LoadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open identity file: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse identity file %s: %w", path, err)
	}
	return ids, nil
}

// Encrypt returns a writer that age-encrypts into dst. Close it to flush the last chunk.
func Encrypt(dst io.Writer, recipients []age.Recipient) (io.WriteCloser, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no age recipients")
	}
	return age.Encrypt(dst, recipients...)
}

// Decrypt returns a reader of the plaintext. A truncated or tampered stream
// fails with an error before or at EOF (age authenticates every chunk).
func Decrypt(src io.Reader, ids []age.Identity) (io.Reader, error) {
	r, err := age.Decrypt(src, ids...)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	return r, nil
}

// Hasher is an io.Writer that tracks sha256 and byte count of what passes through.
type Hasher struct {
	h hash.Hash
	n int64
}

func NewHasher() *Hasher { return &Hasher{h: sha256.New()} }

func (h *Hasher) Write(p []byte) (int, error) {
	h.n += int64(len(p))
	return h.h.Write(p)
}

func (h *Hasher) Sum() string { return hex.EncodeToString(h.h.Sum(nil)) }
func (h *Hasher) Size() int64 { return h.n }

// GenerateKey writes a new X25519 key pair: the public key to pubPath and the
// identity (private key) to keyPath with 0600 permissions. Existing files are
// never overwritten.
func GenerateKey(pubPath, keyPath string) (string, error) {
	for _, p := range []string{pubPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			return "", fmt.Errorf("%s already exists; refusing to overwrite a key", p)
		}
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	pub := id.Recipient().String()
	for _, p := range []string{pubPath, keyPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return "", err
		}
	}
	keyBody := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n", time.Now().UTC().Format(time.RFC3339), pub, id.String())
	if err := writeExclusive(keyPath, []byte(keyBody), 0o600); err != nil {
		return "", err
	}
	if err := writeExclusive(pubPath, []byte(pub+"\n"), 0o644); err != nil {
		return "", err
	}
	return pub, nil
}

func writeExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
