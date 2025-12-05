package session

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"adel/config"
	"adel/models"

	"github.com/go-ldap/ldap/v3"
)

// Session represents an active user session with LDAP connection
type Session struct {
	ID         string
	Username   string
	UserDN     string
	Conn       *ldap.Conn
	CreatedAt  time.Time
	LastAccess time.Time
	ExpiresAt  time.Time
}

// Manager manages user sessions and their LDAP connections
type Manager struct {
	sessions    map[string]*Session
	mu          sync.RWMutex
	cfg         *config.Config
	sessionTTL  time.Duration
	cleanupStop chan struct{}
}

// NewManager creates a new session manager
func NewManager(cfg *config.Config) *Manager {
	m := &Manager{
		sessions:    make(map[string]*Session),
		cfg:         cfg,
		sessionTTL:  30 * time.Minute, // Default session TTL
		cleanupStop: make(chan struct{}),
	}

	// Start cleanup goroutine
	go m.cleanupExpiredSessions()

	return m
}

// Login authenticates a user against AD and creates a new session
func (m *Manager) Login(username, password string) (*Session, error) {
	// Create LDAP connection
	conn, err := m.createLDAPConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to AD: %w", err)
	}

	// Build the bind DN
	// Try different formats: UPN, SAMAccountName@domain, or full DN
	bindDN := username
	if !containsAt(username) && !isDN(username) {
		// If it's just a username, append the domain from BaseDN
		domain := extractDomainFromBaseDN(m.cfg.AD.BaseDN)
		if domain != "" {
			bindDN = username + "@" + domain
		}
	}

	// Attempt to bind
	err = conn.Bind(bindDN, password)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Get user DN after successful bind
	userDN, err := m.findUserDN(conn, username)
	if err != nil {
		// Use bindDN as fallback
		userDN = bindDN
	}

	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Create session
	now := time.Now()
	session := &Session{
		ID:         sessionID,
		Username:   username,
		UserDN:     userDN,
		Conn:       conn,
		CreatedAt:  now,
		LastAccess: now,
		ExpiresAt:  now.Add(m.sessionTTL),
	}

	// Store session
	m.mu.Lock()
	m.sessions[sessionID] = session
	m.mu.Unlock()

	slog.Info("User logged in successfully",
		"username", username,
		"session_id", sessionID,
	)
	return session, nil
}

// Logout terminates a user session and closes the LDAP connection
func (m *Manager) Logout(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	// Close LDAP connection
	if session.Conn != nil {
		session.Conn.Close()
	}

	// Remove session
	delete(m.sessions, sessionID)

	slog.Info("User logged out",
		"username", session.Username,
		"session_id", sessionID,
	)
	return nil
}

// GetSession retrieves a session by ID and updates last access time
func (m *Manager) GetSession(sessionID string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		// Close connection and remove session
		if session.Conn != nil {
			session.Conn.Close()
		}
		delete(m.sessions, sessionID)
		return nil, fmt.Errorf("session expired")
	}

	// Update last access time and extend expiration
	session.LastAccess = time.Now()
	session.ExpiresAt = time.Now().Add(m.sessionTTL)

	return session, nil
}

// GetSessionInfo returns session information without the connection
func (m *Manager) GetSessionInfo(sessionID string) (*models.SessionInfo, error) {
	session, err := m.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	return &models.SessionInfo{
		SessionID: session.ID,
		Username:  session.Username,
		UserDN:    session.UserDN,
		CreatedAt: session.CreatedAt,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

// createLDAPConnection creates a new LDAP connection
func (m *Manager) createLDAPConnection() (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	address := fmt.Sprintf("%s:%d", m.cfg.AD.Server, m.cfg.AD.Port)

	if m.cfg.AD.UseSSL {
		// LDAPS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: m.cfg.AD.SkipTLS, // #nosec G402
			ServerName:         m.cfg.AD.Server,
		}

		// Load CA certificate if provided
		if m.cfg.AD.CACertPath != "" {
			caCert, err := os.ReadFile(m.cfg.AD.CACertPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}

		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		// Plain LDAP connection
		conn, err = ldap.Dial("tcp", address)

		// Optionally upgrade to TLS via StartTLS
		if err == nil && !m.cfg.AD.SkipTLS {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true, // #nosec G402
				ServerName:         m.cfg.AD.Server,
			}
			err = conn.StartTLS(tlsConfig)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	return conn, nil
}

// findUserDN finds the full DN for a user
func (m *Manager) findUserDN(conn *ldap.Conn, username string) (string, error) {
	// Search for the user
	searchRequest := ldap.NewSearchRequest(
		m.cfg.AD.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(&%s(|(sAMAccountName=%s)(userPrincipalName=%s)))",
			m.cfg.AD.UserFilter, ldap.EscapeFilter(username), ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("user not found")
	}

	return sr.Entries[0].DN, nil
}

// cleanupExpiredSessions periodically removes expired sessions
func (m *Manager) cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for id, session := range m.sessions {
				if now.After(session.ExpiresAt) {
					if session.Conn != nil {
						session.Conn.Close()
					}
					delete(m.sessions, id)
					slog.Debug("Cleaned up expired session",
						"session_id", id,
						"username", session.Username,
					)
				}
			}
			m.mu.Unlock()
		case <-m.cleanupStop:
			return
		}
	}
}

// Stop stops the session manager and closes all connections
func (m *Manager) Stop() {
	close(m.cleanupStop)

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, session := range m.sessions {
		if session.Conn != nil {
			session.Conn.Close()
		}
	}
	m.sessions = make(map[string]*Session)
}

// ActiveSessions returns the number of active sessions
func (m *Manager) ActiveSessions() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// generateSessionID generates a secure random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// containsAt checks if a string contains @
func containsAt(s string) bool {
	for _, c := range s {
		if c == '@' {
			return true
		}
	}
	return false
}

// isDN checks if a string looks like a DN
func isDN(s string) bool {
	return len(s) > 3 && (s[0:3] == "CN=" || s[0:3] == "cn=")
}

// extractDomainFromBaseDN extracts domain from base DN
// e.g., "dc=example,dc=com" -> "example.com"
func extractDomainFromBaseDN(baseDN string) string {
	var parts []string
	for _, part := range splitDN(baseDN) {
		if len(part) > 3 && (part[0:3] == "DC=" || part[0:3] == "dc=") {
			parts = append(parts, part[3:])
		}
	}
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += "." + parts[i]
	}
	return result
}

// splitDN splits a DN into its components
func splitDN(dn string) []string {
	var parts []string
	var current string
	escape := false

	for _, c := range dn {
		if escape {
			current += string(c)
			escape = false
			continue
		}
		if c == '\\' {
			escape = true
			current += string(c)
			continue
		}
		if c == ',' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
			continue
		}
		current += string(c)
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
