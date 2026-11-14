package store

import (
	"path/filepath"
	"testing"
)

// The server must reopen its database after a restart (this crashed once with WAL mode).
func TestReopenAfterRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.db")
	for i := 0; i < 3; i++ {
		s, err := Open(p)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if err := s.AddAudit(Audit{At: "t", Event: "start"}); err != nil {
			t.Fatal(err)
		}
		n, _ := s.AuditCount()
		if n != i+1 {
			t.Fatalf("after %d opens: %d entries", i+1, n)
		}
		s.Close()
	}
}
