package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
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
	"adel/version"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/mux"
)

// Fixture values shared by handler tests.
const (
	testUsername      = "testuser"
	testEngLeadDN     = "CN=engineering-lead,OU=Groups,DC=example,DC=com"
	testEmployeesDN   = "CN=Employees,OU=Groups,DC=example,DC=com"
	testAdminsCN      = "Admins"
	testMemberCN      = "Ann Lee"
	testShortDN       = "CN=A,DC=x"
	testBlank         = "   "
	varKeyGroupName   = "groupName"
	attrNameObjectCls = "objectClass"
	classUser         = "user"
)

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

func TestEncodeADPassword(t *testing.T) {
	got := encodeADPassword("A1!")
	want := []byte{'"', 0, 'A', 0, '1', 0, '!', 0, '"', 0}
	if string(got) != string(want) {
		t.Errorf("encodeADPassword() = %v, want %v", got, want)
	}
}

func TestChangeUserPasswordRequiresCurrentPassword(t *testing.T) {
	h := NewHandler(&config.Config{}, nil)
	sess := &session.Session{Username: testUsername, UserDN: "CN=Test User,DC=example,DC=com"}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/change-password", strings.NewReader(`{"newPassword":"Example1!"}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.SessionContextKey, sess))
	rr := httptest.NewRecorder()

	h.ChangeUserPassword(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestResetUserPasswordAuthorizationAndValidation(t *testing.T) {
	t.Run("rejects a caller outside allowed groups", func(t *testing.T) {
		h := NewHandler(&config.Config{AD: config.ADConfig{
			PasswordResetAllowedGroups: []string{"Service Desk"},
		}}, nil)
		sess := &session.Session{Username: testUsername, MemberOf: []string{testEmployeesDN}}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/target/reset-password", strings.NewReader(`{"newPassword":"Example1!"}`))
		req = mux.SetURLVars(req, map[string]string{"username": "target"}) //nolint:goconst // test fixture value
		req = req.WithContext(context.WithValue(req.Context(), middleware.SessionContextKey, sess))
		rr := httptest.NewRecorder()

		h.ResetUserPassword(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
		}
	})

	t.Run("requires a new password for an allowed caller", func(t *testing.T) {
		h := NewHandler(&config.Config{AD: config.ADConfig{
			PasswordResetAllowedGroups: []string{"Employees"},
		}}, nil)
		sess := &session.Session{Username: testUsername, MemberOf: []string{testEmployeesDN}}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/target/reset-password", strings.NewReader(`{}`))
		req = mux.SetURLVars(req, map[string]string{"username": "target"})
		req = req.WithContext(context.WithValue(req.Context(), middleware.SessionContextKey, sess))
		rr := httptest.NewRecorder()

		h.ResetUserPassword(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}

func TestResetUserPasswordWritesAuditLog(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)

	h := NewHandler(&config.Config{AD: config.ADConfig{
		PasswordResetAllowedGroups: []string{"Service Desk"},
	}}, nil)
	sess := &session.Session{Username: "operator", MemberOf: []string{testEmployeesDN}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/target/reset-password", strings.NewReader(`{"newPassword":"Example1!"}`))
	req = mux.SetURLVars(req, map[string]string{"username": "target"})
	req = req.WithContext(context.WithValue(req.Context(), middleware.SessionContextKey, sess))

	h.ResetUserPassword(httptest.NewRecorder(), req)

	for _, field := range []string{`"reset_by":"operator"`, `"target":"target"`, `"status":"denied"`} {
		if !strings.Contains(logs.String(), field) {
			t.Errorf("audit log %q does not contain %s", logs.String(), field)
		}
	}
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
	// Not compared against a literal: the value is stamped in at build time.
	if resp.Version != version.Version {
		t.Errorf("Version = %q, want %q", resp.Version, version.Version)
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
		MemberOf: []string{testEmployeesDN},
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

// leadConfig returns a config using the shipped lead/PM defaults, with search
// restricted so the lead grant is the only way in.
func leadConfig() *config.Config {
	return &config.Config{
		AD: config.ADConfig{
			SearchAllowedGroups: []string{"Helpdesk"},
			LeadGroupSuffixes:   []string{"-lead", "-pm"},
			LeadGroupWildcard:   "-*",
		},
	}
}

// TestGroupMembershipHidesOutOfScopeUser is the core guarantee for user lookups: a lead
// asking about someone outside their teams gets "not found" rather than that user's data.
func TestGroupMembershipHidesOutOfScopeUser(t *testing.T) {
	h := NewHandler(leadConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/membership/outsider", nil)
	req = mux.SetURLVars(req, map[string]string{"username": "outsider"})
	sess := &session.Session{
		Username: testUsername,
		MemberOf: []string{testEngLeadDN},
	}
	ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
	rr := httptest.NewRecorder()

	h.GroupMembership(rr, req.WithContext(ctx))

	// A lead is not denied outright (that would be 403); the lookup proceeds and fails
	// closed on the nil connection. What must never happen is a 200 exposing the target.
	if rr.Code == http.StatusOK {
		t.Error("an out-of-scope user lookup must not return data")
	}
}

// TestSharesLeadScope covers the subordinate test used to gate user lookups.
func TestSharesLeadScope(t *testing.T) {
	h := NewHandler(leadConfig(), nil)
	sess := &session.Session{
		Username: testUsername,
		MemberOf: []string{testEngLeadDN},
	}

	subordinate := []string{"CN=engineering-devs,OU=Groups,DC=example,DC=com"}
	if !h.sharesLeadScope(sess, subordinate) {
		t.Error("a member of engineering-devs should be in an engineering lead's scope")
	}

	outsider := []string{"CN=finance-team,OU=Groups,DC=example,DC=com"}
	if h.sharesLeadScope(sess, outsider) {
		t.Error("a member of finance-team should be outside an engineering lead's scope")
	}

	if h.sharesLeadScope(sess, []string{"not a dn"}) {
		t.Error("a malformed DN should not grant scope")
	}
}

// TestFilterToLeadScope checks that out-of-scope memberships are withheld.
func TestFilterToLeadScope(t *testing.T) {
	h := NewHandler(leadConfig(), nil)
	sess := &session.Session{
		Username: testUsername,
		MemberOf: []string{testEngLeadDN},
	}

	got := h.filterToLeadScope(sess, []string{
		"CN=engineering-devs,OU=Groups,DC=example,DC=com",
		"CN=finance-team,OU=Groups,DC=example,DC=com",
		"CN=engineering,OU=Groups,DC=example,DC=com",
	})

	if len(got) != 2 {
		t.Fatalf("filterToLeadScope() = %v, want 2 in-scope groups", got)
	}
	for _, dn := range got {
		if strings.Contains(dn, "finance") {
			t.Errorf("filterToLeadScope() leaked an out-of-scope group: %q", dn)
		}
	}
}

func TestTeamRequiresSession(t *testing.T) {
	h := NewHandler(leadConfig(), nil)

	rr := httptest.NewRecorder()
	h.Team(rr, httptest.NewRequest(http.MethodGet, "/api/v1/team", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestTeamEmptyForNonLead confirms the endpoint is inert for a user with no role: it
// returns an empty team rather than falling through to a directory listing.
func TestTeamEmptyForNonLead(t *testing.T) {
	h := NewHandler(leadConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/team", nil)
	sess := &session.Session{Username: testUsername, MemberOf: []string{testEmployeesDN}}
	ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
	rr := httptest.NewRecorder()

	h.Team(rr, req.WithContext(ctx))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp models.TeamResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Error("response should succeed with an empty team")
	}
	if len(resp.Groups) != 0 || resp.MemberCount != 0 {
		t.Errorf("non-lead team = %+v, want empty", resp)
	}
}

// TestSearchDeniedForPlainMember confirms non-leads outside the allow-list stay denied.
func TestSearchDeniedForPlainMember(t *testing.T) {
	h := NewHandler(leadConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?query=user", nil)
	sess := &session.Session{Username: testUsername, MemberOf: []string{testEmployeesDN}}
	ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
	rr := httptest.NewRecorder()

	h.Search(rr, req.WithContext(ctx))

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestGroupMembershipRequiresSession(t *testing.T) {
	h := NewHandler(leadConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/membership", nil)
	rr := httptest.NewRecorder()

	h.GroupMembership(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestGroupMembershipForbidsLookupOfOthers(t *testing.T) {
	h := NewHandler(leadConfig(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/membership/someone", nil)
	req = mux.SetURLVars(req, map[string]string{"username": "someone"})
	sess := &session.Session{
		Username: testUsername,
		MemberOf: []string{testEmployeesDN},
	}
	ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
	rr := httptest.NewRecorder()

	h.GroupMembership(rr, req.WithContext(ctx))

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
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
		MemberOf: []string{testEmployeesDN},
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
	cfg := &config.Config{AD: config.ADConfig{GroupFilter: "(objectClass=group)"}} //nolint:goconst // lDAP field
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
	valid := "CN=Admins,OU=Groups,DC=example,DC=com" //nolint:goconst // test fixture data
	other := "CN=Staff,OU=Groups,DC=example,DC=com"

	tests := []struct {
		name  string
		input []string
		limit int
		want  []string
	}{
		{
			name:  "drops blank and malformed entries",
			input: []string{"", testBlank, "not-a-valid-dn", valid},
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
	got := countNonEmpty([]string{"a", "", testBlank, "b"})
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
			{Name: "cn", Values: []string{testAdminsCN}},
			{Name: "description", Values: []string{"Administrators"}}, //nolint:goconst // test fixture data
		},
	}

	groups := h.entriesToGroups([]*ldap.Entry{entry})

	if len(groups) != 1 {
		t.Fatalf("entriesToGroups() returned %d groups, want 1", len(groups))
	}
	if groups[0].CN != testAdminsCN || groups[0].Description != "Administrators" {
		t.Errorf("group = %+v, want cn=Admins description=Administrators", groups[0])
	}
	if groups[0].Nested {
		t.Error("Nested = true, want false for a directly resolved group")
	}
}

// Group inspection exposes directory contents beyond the caller's own memberships, so
// it must sit behind the same allow-list as listing.
func TestGetGroupForbiddenOutsideAllowedGroups(t *testing.T) {
	cfg := &config.Config{
		AD: config.ADConfig{
			SearchAllowedGroups: []string{"infrastructure-services"},
		},
	}
	h := NewHandler(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/Admins", nil)
	req = mux.SetURLVars(req, map[string]string{varKeyGroupName: testAdminsCN})
	sess := &session.Session{
		Username: testUsername,
		MemberOf: []string{testEmployeesDN},
	}
	ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
	rr := httptest.NewRecorder()

	h.GetGroup(rr, req.WithContext(ctx))

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	var response models.GroupDetailResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.Success || response.Error == "" {
		t.Errorf("response = %+v, want unsuccessful response with an error", response)
	}
}

func TestGetGroupRequiresSession(t *testing.T) {
	h := NewHandler(&config.Config{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/Admins", nil)
	req = mux.SetURLVars(req, map[string]string{varKeyGroupName: testAdminsCN})
	rr := httptest.NewRecorder()

	h.GetGroup(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// A blank name must be rejected before any LDAP work, so a nil connection cannot panic.
func TestGetGroupRejectsEmptyName(t *testing.T) {
	h := NewHandler(&config.Config{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/%20", nil)
	req = mux.SetURLVars(req, map[string]string{varKeyGroupName: testBlank})
	sess := &session.Session{Username: testUsername}
	ctx := context.WithValue(req.Context(), middleware.SessionContextKey, sess)
	rr := httptest.NewRecorder()

	h.GetGroup(rr, req.WithContext(ctx))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestEntriesToGroupMembers(t *testing.T) {
	h := NewHandler(&config.Config{}, nil)

	entries := []*ldap.Entry{
		{
			DN: "CN=Zoe Smith,OU=Users,DC=example,DC=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"Zoe Smith"}},
				{Name: "sAMAccountName", Values: []string{"zsmith"}},
				{Name: "displayName", Values: []string{"Zoe Smith"}},
				{Name: "mail", Values: []string{"zoe@example.com"}},
				{Name: attrNameObjectCls, Values: []string{"top", "person", classUser}},
			},
		},
		{
			DN: "CN=Nested Group,OU=Groups,DC=example,DC=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"Nested Group"}},
				{Name: attrNameObjectCls, Values: []string{"top", "group"}},
			},
		},
	}

	members := h.entriesToGroupMembers(entries)

	if len(members) != 2 {
		t.Fatalf("entriesToGroupMembers() returned %d members, want 2", len(members))
	}
	// Sorted by display label, so the group sorts ahead of "Zoe Smith".
	if members[0].CN != "Nested Group" {
		t.Errorf("members[0].CN = %q, want %q", members[0].CN, "Nested Group")
	}
	if !members[0].IsGroup {
		t.Error("members[0].IsGroup = false, want true for a group member")
	}
	if members[1].IsGroup {
		t.Error("members[1].IsGroup = true, want false for a user member")
	}
	if members[1].SAMAccountName != "zsmith" {
		t.Errorf("members[1].SAMAccountName = %q, want %q", members[1].SAMAccountName, "zsmith")
	}
}

// Excluded containers and groups must not leak through the member list.
func TestEntriesToGroupMembersAppliesExclusions(t *testing.T) {
	h := NewHandler(&config.Config{
		AD: config.ADConfig{
			ExcludedObjects: []string{"OU=Disabled"},
			ExcludedGroups:  []string{"Secret Group"},
		},
	}, nil)

	entries := []*ldap.Entry{
		{
			DN: "CN=Old User,OU=Disabled,DC=example,DC=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"Old User"}},
				{Name: attrNameObjectCls, Values: []string{classUser}},
			},
		},
		{
			DN: "CN=Secret Group,OU=Groups,DC=example,DC=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"Secret Group"}},
				{Name: attrNameObjectCls, Values: []string{"group"}},
			},
		},
		{
			DN: "CN=Ann Lee,OU=Users,DC=example,DC=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{testMemberCN}},
				{Name: attrNameObjectCls, Values: []string{classUser}},
			},
		},
	}

	members := h.entriesToGroupMembers(entries)

	if len(members) != 1 {
		t.Fatalf("entriesToGroupMembers() returned %d members, want 1", len(members))
	}
	if members[0].CN != testMemberCN {
		t.Errorf("members[0].CN = %q, want %q", members[0].CN, testMemberCN)
	}
}

func TestMemberLabel(t *testing.T) {
	tests := []struct {
		name   string
		member *models.GroupMember
		want   string
	}{
		{
			name:   "prefers display name",
			member: &models.GroupMember{DN: testShortDN, CN: "A", DisplayName: testMemberCN},
			want:   testMemberCN,
		},
		{
			name:   "falls back to CN",
			member: &models.GroupMember{DN: testShortDN, CN: "A"},
			want:   "A",
		},
		{
			name:   "falls back to DN",
			member: &models.GroupMember{DN: testShortDN},
			want:   testShortDN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := memberLabel(tt.member); got != tt.want {
				t.Errorf("memberLabel() = %q, want %q", got, tt.want)
			}
		})
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

// Regression: nested membership must be anchored to the direct groups of the user
// being viewed. The authenticated user's DN must not influence this LDAP request.
func TestNestedGroupSearchRequestUsesViewedUsersGroups(t *testing.T) {
	h := NewHandler(&config.Config{AD: config.ADConfig{
		BaseDN:           "DC=example,DC=com",
		GroupFilter:      "(objectClass=group)",
		MaxSearchResults: 200,
	}}, nil)
	targetGroups := []string{
		"CN=Target Engineering,OU=Groups,DC=example,DC=com",
		"CN=Target Support,OU=Groups,DC=example,DC=com",
	}

	request := h.nestedGroupSearchRequest(targetGroups)

	const want = "(&(objectClass=group)(|(member:1.2.840.113556.1.4.1941:=CN=Target Engineering,OU=Groups,DC=example,DC=com)(member:1.2.840.113556.1.4.1941:=CN=Target Support,OU=Groups,DC=example,DC=com)))"
	if request.Filter != want {
		t.Errorf("nested group filter =\n  %q\nwant\n  %q", request.Filter, want)
	}
}
