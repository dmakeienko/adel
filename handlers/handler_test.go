package handlers

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"adel/config"
	"adel/middleware"
	"adel/models"
	"adel/session"

	"github.com/go-ldap/ldap/v3"
)

// testUsername is the session username shared by handler tests.
const testUsername = "testuser"

func TestIsUserEnabled(t *testing.T) {
	tests := []struct {
		name string
		uac  string
		want bool
	}{
		{"empty string defaults to enabled", "", true},
		{"normal account (512)", "512", true},
		{"disabled account (514)", "514", false},
		{"disabled + password not required (546)", "546", false},
		{"enabled with password doesn't expire (66048)", "66048", true},
		{"invalid value defaults to enabled", "notanumber", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUserEnabled(tt.uac)
			if got != tt.want {
				t.Errorf("isUserEnabled(%q) = %v, want %v", tt.uac, got, tt.want)
			}
		})
	}
}

func TestFiletimeToUnixTime(t *testing.T) {
	t.Run("empty string returns nil", func(t *testing.T) {
		got := filetimeToUnixTime("")
		if got != nil {
			t.Errorf("filetimeToUnixTime(\"\") = %v, want nil", got)
		}
	})

	t.Run("zero returns nil", func(t *testing.T) {
		got := filetimeToUnixTime("0")
		if got != nil {
			t.Errorf("filetimeToUnixTime(\"0\") = %v, want nil", got)
		}
	})

	t.Run("never expires returns nil", func(t *testing.T) {
		got := filetimeToUnixTime("9223372036854775807")
		if got != nil {
			t.Errorf("filetimeToUnixTime(never) = %v, want nil", got)
		}
	})

	t.Run("invalid string returns nil", func(t *testing.T) {
		got := filetimeToUnixTime("notanumber")
		if got != nil {
			t.Errorf("filetimeToUnixTime(invalid) = %v, want nil", got)
		}
	})

	t.Run("value before unix epoch returns nil", func(t *testing.T) {
		got := filetimeToUnixTime("100")
		if got != nil {
			t.Errorf("filetimeToUnixTime(100) = %v, want nil", got)
		}
	})

	t.Run("known filetime converts correctly", func(t *testing.T) {
		// 132500000000000000 = approximately 2020-12-04 in Windows FILETIME
		got := filetimeToUnixTime("132500000000000000")
		if got == nil {
			t.Fatal("filetimeToUnixTime() returned nil for valid filetime")
			return
		}
		// Should be a date around 2020
		if got.Year() < 2020 || got.Year() > 2021 {
			t.Errorf("filetimeToUnixTime() year = %d, expected ~2020", got.Year())
		}
	})
}

func TestConvertUint64ToInt64(t *testing.T) {
	t.Run("valid conversion", func(t *testing.T) {
		got, err := convertUint64ToInt64(42)
		if err != nil || got != 42 {
			t.Errorf("convertUint64ToInt64(42) = %d, %v", got, err)
		}
	})

	t.Run("max int64", func(t *testing.T) {
		got, err := convertUint64ToInt64(uint64(math.MaxInt64))
		if err != nil || got != math.MaxInt64 {
			t.Errorf("convertUint64ToInt64(MaxInt64) = %d, %v", got, err)
		}
	})

	t.Run("overflow returns error", func(t *testing.T) {
		_, err := convertUint64ToInt64(uint64(math.MaxInt64) + 1)
		if err == nil {
			t.Error("convertUint64ToInt64(overflow) should return error")
		}
	})
}

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	data := models.APIResponse{Success: true, Message: "ok"}

	writeJSON(rr, http.StatusOK, data)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var resp models.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success || resp.Message != "ok" {
		t.Errorf("response = %+v, want Success=true, Message=ok", resp)
	}
}

func TestHealthHandler(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Environment: "test"},
		AD:     config.ADConfig{Server: "test-ad", Port: 389}, //nolint:goconst // test fixture data
	}
	h := NewHandler(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	h.Health(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Health status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp models.HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Status = %q, want %q", resp.Status, "healthy")
	}
	if resp.Environment != "test" {
		t.Errorf("Environment = %q, want %q", resp.Environment, "test")
	}
	if resp.ADServer != "test-ad" {
		t.Errorf("ADServer = %q, want %q", resp.ADServer, "test-ad")
	}
	if resp.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestGetUserAttributes(t *testing.T) {
	attrs := getUserAttributes()
	if len(attrs) == 0 {
		t.Fatal("getUserAttributes() returned empty slice")
	}

	// Check some expected attributes are present
	expected := []string{"sAMAccountName", "mail", "displayName", "memberOf", "userAccountControl"} //nolint:goconst // test fixture data
	for _, attr := range expected {
		found := false
		for _, a := range attrs {
			if a == attr {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("getUserAttributes() missing %q", attr)
		}
	}
}

func TestLoginHandlerValidation(t *testing.T) {
	cfg := &config.Config{
		AD: config.ADConfig{Server: "test-ad", Port: 389, BaseDN: "dc=test,dc=com"}, //nolint:goconst // test fixture data
	}
	h := NewHandler(cfg, nil)

	t.Run("invalid json body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		rr := httptest.NewRecorder()
		h.Login(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		body := `{"username":"","password":""}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", stringReader(body))
		rr := httptest.NewRecorder()
		h.Login(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}

func TestSessionInfoHandlerValidation(t *testing.T) {
	cfg := &config.Config{
		AD: config.ADConfig{Server: "test-ad", Port: 389, BaseDN: "dc=test,dc=com"},
	}
	h := NewHandler(cfg, nil)

	t.Run("missing session ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
		rr := httptest.NewRecorder()
		h.SessionInfo(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}

func TestLogoutHandlerValidation(t *testing.T) {
	cfg := &config.Config{
		AD: config.ADConfig{Server: "test-ad", Port: 389, BaseDN: "dc=test,dc=com"},
	}
	h := NewHandler(cfg, nil)

	t.Run("missing session ID in body and header", func(t *testing.T) {
		body := `{}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", stringReader(body))
		rr := httptest.NewRecorder()
		h.Logout(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}

func TestGetCurrentUserNoSession(t *testing.T) {
	cfg := &config.Config{
		AD: config.ADConfig{Server: "test-ad", Port: 389, BaseDN: "dc=test,dc=com"},
	}
	h := NewHandler(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	rr := httptest.NewRecorder()
	h.GetCurrentUser(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestSearchForbiddenOutsideAllowedGroups(t *testing.T) {
	cfg := &config.Config{
		AD: config.ADConfig{
			SearchAllowedGroups: []string{"Helpdesk"},
		},
	}
	h := NewHandler(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?query=user", nil)
	sess := &session.Session{
		Username: testUsername,
		MemberOf: []string{"CN=Employees,OU=Groups,DC=example,DC=com"},
	}
	ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
	rr := httptest.NewRecorder()

	h.Search(rr, req.WithContext(ctx))

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	var response models.SearchResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Success || response.Error == "" {
		t.Errorf("response = %+v, want unsuccessful response with an error", response)
	}
}

// stringReader creates an io.Reader from a string for use in request bodies.
func stringReader(s string) *stringReaderImpl {
	return &stringReaderImpl{data: []byte(s), pos: 0}
}

type stringReaderImpl struct {
	data []byte
	pos  int
}

func (r *stringReaderImpl) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, &eofError{}
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

type eofError struct{}

func (e *eofError) Error() string { return "EOF" }

// Ensure filetimeToUnixTime produces a UTC time.
func TestFiletimeToUnixTimeUTC(t *testing.T) {
	got := filetimeToUnixTime("132500000000000000")
	if got == nil {
		t.Fatal("expected non-nil time")
		return
	}
	if got.Location() != time.UTC {
		t.Errorf("location = %v, want UTC", got.Location())
	}
}

func TestGetAllGroupsForbiddenOutsideAllowedGroups(t *testing.T) {
	cfg := &config.Config{
		AD: config.ADConfig{
			SearchAllowedGroups: []string{"infrastructure-services"},
		},
	}
	h := NewHandler(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups?query=infra", nil)
	sess := &session.Session{
		Username: testUsername,
		MemberOf: []string{"CN=Employees,OU=Groups,DC=example,DC=com"},
	}
	ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
	rr := httptest.NewRecorder()

	h.GetAllGroups(rr, req.WithContext(ctx))

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	var response models.GroupsResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Success || response.Error == "" {
		t.Errorf("response = %+v, want unsuccessful response with an error", response)
	}
}

func TestGetAllGroupsRejectsUnboundedListing(t *testing.T) {
	// An allowed user must still not be able to list the whole directory: the query
	// requirement is a cost control, independent of the search allow-list.
	cfg := &config.Config{AD: config.ADConfig{GroupFilter: "(objectClass=group)"}}
	h := NewHandler(cfg, nil)

	tests := []struct {
		name string
		url  string
	}{
		{"no query", "/api/v1/groups"},
		{"empty query", "/api/v1/groups?query="},
		{"whitespace query", "/api/v1/groups?query=%20%20"},
		{"query below minimum length", "/api/v1/groups?query=a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			sess := &session.Session{Username: testUsername}
			ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
			rr := httptest.NewRecorder()

			h.GetAllGroups(rr, req.WithContext(ctx))

			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
			var response models.GroupsResponse
			if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if response.Success || response.Error == "" {
				t.Errorf("response = %+v, want unsuccessful response with an error", response)
			}
		})
	}
}

func TestResolveGroupsEmptyInputSkipsSearch(t *testing.T) {
	// No valid DNs means no LDAP search, so a nil session connection must not panic.
	cfg := &config.Config{AD: config.ADConfig{GroupFilter: "(objectClass=group)"}}
	h := NewHandler(cfg, nil)

	body := strings.NewReader(`{"dns":["","   ","not-a-valid-dn"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups/resolve", body)
	sess := &session.Session{Username: testUsername}
	ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
	rr := httptest.NewRecorder()

	h.ResolveGroups(rr, req.WithContext(ctx))

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	var response models.GroupsResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !response.Success || response.Count != 0 {
		t.Errorf("response = %+v, want successful empty response", response)
	}
}

func TestResolveGroupsRequiresSession(t *testing.T) {
	h := NewHandler(&config.Config{}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups/resolve",
		strings.NewReader(`{"dns":[]}`))
	rr := httptest.NewRecorder()

	h.ResolveGroups(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestNormalizeDNs(t *testing.T) {
	valid := "CN=Admins,OU=Groups,DC=example,DC=com"
	other := "CN=Staff,OU=Groups,DC=example,DC=com"

	tests := []struct {
		name  string
		input []string
		limit int
		want  []string
	}{
		{
			name:  "drops blank and malformed entries",
			input: []string{"", "   ", "not-a-valid-dn", valid},
			limit: maxResolveDNs,
			want:  []string{valid},
		},
		{
			name:  "trims surrounding whitespace",
			input: []string{"  " + valid + "  "},
			limit: maxResolveDNs,
			want:  []string{valid},
		},
		{
			name:  "de-duplicates case-insensitively",
			input: []string{valid, strings.ToUpper(valid), other},
			limit: maxResolveDNs,
			want:  []string{valid, other},
		},
		{
			name:  "stops at the limit",
			input: []string{valid, other},
			limit: 1,
			want:  []string{valid},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeDNs(tt.input, make(map[string]struct{}), tt.limit)
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeDNs() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("normalizeDNs()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// A DN already present in seen must be rejected. This is what stops nested-group
// expansion from revisiting a group and looping forever on a membership cycle.
func TestNormalizeDNsSkipsAlreadySeen(t *testing.T) {
	dn := "CN=Admins,OU=Groups,DC=example,DC=com"
	seen := map[string]struct{}{strings.ToLower(dn): {}}

	got := normalizeDNs([]string{dn}, seen, maxResolveDNs)

	if len(got) != 0 {
		t.Errorf("normalizeDNs() = %v, want empty for an already-seen DN", got)
	}
}

// Accepted DNs must be recorded in seen so the next hop of the expansion skips them.
func TestNormalizeDNsRecordsAcceptedDNs(t *testing.T) {
	dn := "CN=Admins,OU=Groups,DC=example,DC=com"
	seen := make(map[string]struct{})

	normalizeDNs([]string{dn}, seen, maxResolveDNs)

	if _, ok := seen[strings.ToLower(dn)]; !ok {
		t.Errorf("seen = %v, want it to contain the accepted DN", seen)
	}
}

func TestCountNonEmpty(t *testing.T) {
	got := countNonEmpty([]string{"a", "", "   ", "b"})
	if got != 2 {
		t.Errorf("countNonEmpty() = %d, want 2", got)
	}
}

// Entries map to unmarked direct groups: Nested is applied afterwards, only to the
// extra entries the matching-rule-in-chain search turns up.
func TestEntriesToGroupsProducesDirectGroups(t *testing.T) {
	h := NewHandler(&config.Config{}, nil)

	entry := &ldap.Entry{
		DN: "CN=Admins,OU=Groups,DC=example,DC=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"Admins"}},
			{Name: "description", Values: []string{"Administrators"}},
		},
	}

	groups := h.entriesToGroups([]*ldap.Entry{entry})

	if len(groups) != 1 {
		t.Fatalf("entriesToGroups() returned %d groups, want 1", len(groups))
	}
	if groups[0].CN != "Admins" || groups[0].Description != "Administrators" {
		t.Errorf("group = %+v, want cn=Admins description=Administrators", groups[0])
	}
	if groups[0].Nested {
		t.Error("Nested = true, want false for a directly resolved group")
	}
}

// The nested filter must scope to groups and escape the user DN, since it is built
// from a value that reaches the server verbatim.
func TestNestedGroupFilter(t *testing.T) {
	got := session.NestedGroupFilter("(objectClass=group)", "CN=Bob (Admin),DC=example,DC=com")

	const want = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=CN=Bob \\28Admin\\29,DC=example,DC=com))"
	if got != want {
		t.Errorf("NestedGroupFilter() =\n  %q\nwant\n  %q", got, want)
	}
}
