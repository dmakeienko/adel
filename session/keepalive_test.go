package session

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"adel/config"

	"github.com/go-ldap/ldap/v3"
)

// newPipeConn returns an LDAP connection over an in-memory pipe and the server end
// of that pipe. Closing the server end simulates the directory dropping the
// connection.
func newPipeConn(t *testing.T) (*ldap.Conn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	conn := ldap.NewConn(client, false)
	conn.Start()
	t.Cleanup(func() {
		conn.Close()
		server.Close()
	})
	return conn, server
}

// closeAndWait closes the server end and waits for the client to notice.
func closeAndWait(t *testing.T, conn *ldap.Conn, server net.Conn) {
	t.Helper()
	server.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !conn.IsClosing() {
		if time.Now().After(deadline) {
			t.Fatal("connection did not register the close")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// newTestManager builds a manager without background goroutines doing anything
// time-sensitive during the test.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(&config.Config{Session: config.SessionConfig{TTL: time.Hour}})
	t.Cleanup(m.Stop)
	return m
}

func addSession(m *Manager, id string, conn *ldap.Conn, expiresAt time.Time) *Session {
	s := &Session{ID: id, Username: "user-" + id, Conn: conn, ExpiresAt: expiresAt}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s
}

func TestGetSessionEndsSessionWithClosedConnection(t *testing.T) {
	m := newTestManager(t)
	conn, server := newPipeConn(t)
	addSession(m, "s1", conn, time.Now().Add(time.Hour))
	closeAndWait(t, conn, server)

	if _, err := m.GetSession("s1"); !errors.Is(err, ErrConnectionLost) {
		t.Fatalf("GetSession() error = %v, want %v", err, ErrConnectionLost)
	}
	if n := m.ActiveSessions(); n != 0 {
		t.Errorf("ActiveSessions() = %d, want 0", n)
	}
}

func TestGetSessionKeepsSessionWithOpenConnection(t *testing.T) {
	m := newTestManager(t)
	conn, _ := newPipeConn(t)
	addSession(m, "s1", conn, time.Now().Add(time.Hour))

	if _, err := m.GetSession("s1"); err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
}

func TestPingSessions(t *testing.T) {
	networkErr := ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset"))
	ldapErr := ldap.NewError(ldap.LDAPResultBusy, errors.New("busy"))

	tests := []struct {
		name     string
		pingErr  error
		wantKept bool
	}{
		{"successful ping keeps session", nil, true},
		{"network error ends session", networkErr, false},
		{"non-network LDAP error keeps session", ldapErr, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestManager(t)
			conn, _ := newPipeConn(t)
			expiresAt := time.Now().Add(time.Hour)
			s := addSession(m, "s1", conn, expiresAt)
			m.pingConn = func(*ldap.Conn) error { return tt.pingErr }

			m.pingSessions()

			m.mu.RLock()
			_, kept := m.sessions["s1"]
			m.mu.RUnlock()
			if kept != tt.wantKept {
				t.Errorf("session kept = %v, want %v", kept, tt.wantKept)
			}
			if kept && !s.ExpiresAt.Equal(expiresAt) {
				t.Errorf("keepalive changed ExpiresAt to %v, want %v", s.ExpiresAt, expiresAt)
			}
		})
	}
}

func TestPingSessionsSkipsExpiredAndDropsClosed(t *testing.T) {
	m := newTestManager(t)
	expiredConn, _ := newPipeConn(t)
	closedConn, closedServer := newPipeConn(t)
	addSession(m, "expired", expiredConn, time.Now().Add(-time.Minute))
	addSession(m, "closed", closedConn, time.Now().Add(time.Hour))
	closeAndWait(t, closedConn, closedServer)

	var pings atomic.Int32
	m.pingConn = func(*ldap.Conn) error {
		pings.Add(1)
		return nil
	}

	m.pingSessions()

	if n := pings.Load(); n != 0 {
		t.Errorf("pinged %d connections, want 0", n)
	}
	m.mu.RLock()
	_, closedKept := m.sessions["closed"]
	m.mu.RUnlock()
	if closedKept {
		t.Error("session with a closed connection was kept")
	}
}

func TestPingRootDSEOnDeadConnectionIsNetworkError(t *testing.T) {
	conn, server := newPipeConn(t)
	closeAndWait(t, conn, server)

	err := pingRootDSE(conn)
	if !ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		t.Fatalf("pingRootDSE() error = %v, want a network error", err)
	}
}

func TestKeepaliveDisabledByDefaultConfig(t *testing.T) {
	m := newTestManager(t)
	if m.keepalive != 0 {
		t.Errorf("keepalive = %v, want 0 when not configured", m.keepalive)
	}
}
