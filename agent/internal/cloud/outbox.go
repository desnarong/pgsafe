package cloud

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// Outbox is a durable queue of reports (state_dir/outbox.jsonl). Reports are
// written here first and sent in order, so the control plane being down never
// affects a backup — they are delivered later.
type Outbox struct {
	path string
	lock string
}

type item struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
	Queued time.Time       `json:"queued"`
}

func NewOutbox(stateDir string) *Outbox {
	return &Outbox{path: filepath.Join(stateDir, "outbox.jsonl"), lock: filepath.Join(stateDir, "locks", "outbox.lock")}
}

// withLock serializes outbox access across processes (CLI + daemon).
func (o *Outbox) withLock(ctx context.Context, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(o.lock), 0o700); err != nil {
		return err
	}
	fl := flock.New(o.lock)
	ok, err := fl.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("outbox busy")
	}
	defer fl.Unlock()
	return fn()
}

// Enqueue appends a request.
func (o *Outbox) Enqueue(ctx context.Context, method, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	line, _ := json.Marshal(item{Method: method, Path: path, Body: b, Queued: time.Now().UTC()})
	return o.withLock(ctx, func() error {
		if err := os.MkdirAll(filepath.Dir(o.path), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(o.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	})
}

// Flush sends queued requests in order, stopping at the first transient
// failure. Requests the server rejects permanently (4xx) are dropped.
func (o *Outbox) Flush(ctx context.Context, c *Client) (sent, dropped, pending int, err error) {
	err = o.withLock(ctx, func() error {
		data, err := os.ReadFile(o.path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		var items []item
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		for sc.Scan() {
			var it item
			if json.Unmarshal(sc.Bytes(), &it) == nil {
				items = append(items, it)
			}
		}
		i := 0
		var sendErr error
		for ; i < len(items); i++ {
			rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			e := c.do(rctx, items[i].Method, items[i].Path, items[i].Body, nil)
			cancel()
			var ae *APIError
			switch {
			case e == nil:
				sent++
			case errors.As(e, &ae) && ae.Permanent():
				dropped++
			default:
				sendErr = e
			}
			if sendErr != nil {
				break
			}
		}
		rest := items[i:]
		pending = len(rest)
		if err := o.rewrite(rest); err != nil {
			return err
		}
		return sendErr
	})
	return sent, dropped, pending, err
}

func (o *Outbox) rewrite(items []item) error {
	if len(items) == 0 {
		err := os.Remove(o.path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var buf bytes.Buffer
	for _, it := range items {
		line, _ := json.Marshal(it)
		buf.Write(append(line, '\n'))
	}
	tmp := o.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, o.path)
}

// Len returns the number of queued requests.
func (o *Outbox) Len() int {
	data, err := os.ReadFile(o.path)
	if err != nil {
		return 0
	}
	return bytes.Count(data, []byte("\n"))
}
