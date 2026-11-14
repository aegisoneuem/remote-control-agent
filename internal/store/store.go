// Package store keeps the RC server's state in SQLite (pure Go, no CGO): operators, policy,
// the audit log and recording metadata. The schema mirrors the proposed migration
// 0023_remote_control.sql (rc_sessions, rc_participants) closely enough to port to Postgres:
// plain tables, TEXT/INTEGER columns, no SQLite-only features in the queries.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

// Schema version 1. Each statement is idempotent so Open can run it on every start.
var schema = []string{
	`CREATE TABLE IF NOT EXISTS operators (
		id TEXT PRIMARY KEY, name TEXT NOT NULL, token_sha256 TEXT NOT NULL UNIQUE,
		perms TEXT NOT NULL, created_at TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, event TEXT NOT NULL,
		operator TEXT NOT NULL DEFAULT '', device TEXT NOT NULL DEFAULT '', session TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX IF NOT EXISTS audit_session ON audit(session)`,
	`CREATE INDEX IF NOT EXISTS audit_at ON audit(at)`,
	`CREATE TABLE IF NOT EXISTS recordings (
		session TEXT PRIMARY KEY, device TEXT NOT NULL, operator TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '',
		started_at TEXT NOT NULL, ended_at TEXT NOT NULL DEFAULT '', duration_ms INTEGER NOT NULL DEFAULT 0,
		chunks INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, width INTEGER NOT NULL DEFAULT 0, height INTEGER NOT NULL DEFAULT 0,
		key_id TEXT NOT NULL, eph_pub TEXT NOT NULL, wrapped_key TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'recording', expires_at TEXT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS recordings_expires ON recordings(expires_at)`,
}

type Store struct{ db *sql.DB }

type Operator struct {
	ID, Name, TokenHash string
	Perms               []string
	Disabled            bool
}

type Audit struct {
	At, Event, Operator, Device, Session, Detail string
}

type Recording struct {
	Session, Device, Operator, Reason string
	Started, Ended                    time.Time
	DurationMS                        int64
	Chunks, Bytes                     int64
	Width, Height                     int
	KeyID, EphPub, WrappedKey         string
	Status                            string // recording, complete
	Expires                           time.Time
}

const ts = time.RFC3339Nano

func Open(path string) (*Store, error) {
	// Rollback journal (DELETE) rather than WAL: the pure-Go driver's WAL shared-memory index is
	// not reliable across restarts on every platform, and one writer does not need WAL.
	db, err := sql.Open("sqlite3", "file:"+path+"?_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; serialising here avoids SQLITE_BUSY under load
	for _, q := range schema {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, fmt.Errorf("schema: %w", err)
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

/* operators */

func (s *Store) Operators() ([]Operator, error) {
	rows, err := s.db.Query(`SELECT id, name, token_sha256, perms, disabled FROM operators ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Operator
	for rows.Next() {
		var o Operator
		var perms string
		if err := rows.Scan(&o.ID, &o.Name, &o.TokenHash, &perms, &o.Disabled); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(perms), &o.Perms)
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) PutOperator(o Operator) error {
	p, _ := json.Marshal(o.Perms)
	_, err := s.db.Exec(`INSERT INTO operators(id, name, token_sha256, perms, created_at, disabled) VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, token_sha256=excluded.token_sha256, perms=excluded.perms, disabled=excluded.disabled`,
		o.ID, o.Name, o.TokenHash, string(p), time.Now().UTC().Format(ts), o.Disabled)
	return err
}

/* settings (policy and similar small documents) */

func (s *Store) Get(k string, v any) (bool, error) {
	var raw string
	err := s.db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), v)
}

func (s *Store) Put(k string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO settings(k, v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, string(b))
	return err
}

/* audit */

func (s *Store) AddAudit(e Audit) error {
	_, err := s.db.Exec(`INSERT INTO audit(at, event, operator, device, session, detail) VALUES(?,?,?,?,?,?)`,
		e.At, e.Event, e.Operator, e.Device, e.Session, e.Detail)
	return err
}

// RecentAudit returns the newest n entries, oldest first.
func (s *Store) RecentAudit(n int) ([]Audit, error) {
	rows, err := s.db.Query(`SELECT at, event, operator, device, session, detail FROM
		(SELECT * FROM audit ORDER BY id DESC LIMIT ?) ORDER BY id`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Audit
	for rows.Next() {
		var e Audit
		if err := rows.Scan(&e.At, &e.Event, &e.Operator, &e.Device, &e.Session, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AuditCount() (int, error) {
	var n int
	return n, s.db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&n)
}

/* recordings */

func (s *Store) StartRecording(r Recording) error {
	_, err := s.db.Exec(`INSERT INTO recordings(session, device, operator, reason, started_at, width, height, key_id, eph_pub, wrapped_key, status, expires_at)
		VALUES(?,?,?,?,?,?,?,?,?,?, 'recording', ?)
		ON CONFLICT(session) DO NOTHING`,
		r.Session, r.Device, r.Operator, r.Reason, r.Started.UTC().Format(ts), r.Width, r.Height, r.KeyID, r.EphPub, r.WrappedKey, r.Expires.UTC().Format(ts))
	return err
}

func (s *Store) AddChunk(session string, n, size int64) error {
	_, err := s.db.Exec(`UPDATE recordings SET chunks=MAX(chunks, ?), bytes=bytes+? WHERE session=? AND status='recording'`, n+1, size, session)
	return err
}

func (s *Store) FinishRecording(session string, ended time.Time, durMS int64) error {
	_, err := s.db.Exec(`UPDATE recordings SET status='complete', ended_at=?, duration_ms=? WHERE session=?`, ended.UTC().Format(ts), durMS, session)
	return err
}

func scanRec(sc interface{ Scan(...any) error }) (Recording, error) {
	var r Recording
	var st, en, ex string
	err := sc.Scan(&r.Session, &r.Device, &r.Operator, &r.Reason, &st, &en, &r.DurationMS, &r.Chunks, &r.Bytes, &r.Width, &r.Height,
		&r.KeyID, &r.EphPub, &r.WrappedKey, &r.Status, &ex)
	r.Started, _ = time.Parse(ts, st)
	r.Ended, _ = time.Parse(ts, en)
	r.Expires, _ = time.Parse(ts, ex)
	return r, err
}

const recCols = `session, device, operator, reason, started_at, ended_at, duration_ms, chunks, bytes, width, height, key_id, eph_pub, wrapped_key, status, expires_at`

func (s *Store) Recording(session string) (Recording, bool, error) {
	r, err := scanRec(s.db.QueryRow(`SELECT `+recCols+` FROM recordings WHERE session=?`, session))
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

func (s *Store) Recordings(limit int) ([]Recording, error) {
	rows, err := s.db.Query(`SELECT `+recCols+` FROM recordings ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Recording
	for rows.Next() {
		r, err := scanRec(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ExpiredRecordings lists recordings past their retention date.
func (s *Store) ExpiredRecordings(now time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT session FROM recordings WHERE expires_at < ?`, now.UTC().Format(ts))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRecording(session string) error {
	_, err := s.db.Exec(`DELETE FROM recordings WHERE session=?`, session)
	return err
}
