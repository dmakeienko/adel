package handlers

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"adel/config"
	"adel/models"
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
		AD:     config.ADConfig{Server: "test-ad", Port: 389},
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
	expected := []string{"sAMAccountName", "mail", "displayName", "memberOf", "userAccountControl"}
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
		AD: config.ADConfig{Server: "test-ad", Port: 389, BaseDN: "dc=test,dc=com"},
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
	}
	if got.Location() != time.UTC {
		t.Errorf("location = %v, want UTC", got.Location())
	}
}
