package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreOperatorsAuditRetention(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.PutOperator(Operator{ID: "op-a", Name: "A", TokenHash: "h1", Perms: []string{"x", "y"}}); err != nil {
		t.Fatal(err)
	}
	ops, _ := s.Operators()
	if len(ops) != 1 || ops[0].Perms[1] != "y" {
		t.Fatalf("operators %+v", ops)
	}
	for i := 0; i < 5; i++ {
		_ = s.AddAudit(Audit{At: "t", Event: "e", Detail: string(rune('a' + i))})
	}
	last, _ := s.RecentAudit(2)
	if len(last) != 2 || last[0].Detail != "d" || last[1].Detail != "e" {
		t.Fatalf("recent audit %+v", last)
	}
	now := time.Now()
	_ = s.StartRecording(Recording{Session: "RC-000001", Device: "D", Started: now, KeyID: "k", EphPub: "e", WrappedKey: "w", Expires: now.Add(-time.Hour)})
	_ = s.StartRecording(Recording{Session: "RC-000002", Device: "D", Started: now, KeyID: "k", EphPub: "e", WrappedKey: "w", Expires: now.Add(time.Hour)})
	_ = s.AddChunk("RC-000002", 0, 100)
	_ = s.FinishRecording("RC-000002", now, 5000)
	exp, _ := s.ExpiredRecordings(now)
	if len(exp) != 1 || exp[0] != "RC-000001" {
		t.Fatalf("expired %v", exp)
	}
	r, ok, _ := s.Recording("RC-000002")
	if !ok || r.Status != "complete" || r.Chunks != 1 || r.Bytes != 100 || r.DurationMS != 5000 {
		t.Fatalf("recording %+v", r)
	}
	_ = s.DeleteRecording("RC-000001")
	if rs, _ := s.Recordings(10); len(rs) != 1 {
		t.Fatalf("after delete %d", len(rs))
	}
}
