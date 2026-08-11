package main

import (
	"log/slog"
	"net/http"
	"testing"

	"adel/config"
	"adel/handlers"

	"github.com/gorilla/mux"
)

// The wildcard /groups/{groupName} is registered after the literal group sub-routes and
// would swallow them if that order were ever changed, which no handler test would catch.
func TestGroupRouteOrdering(t *testing.T) {
	cfg := &config.Config{AD: config.ADConfig{Server: "test-ad", BaseDN: "dc=test,dc=com"}}
	router := setupRouter(handlers.NewHandler(cfg, nil), nil, cfg)

	tests := []struct {
		method  string
		path    string
		wantVar string // empty means a literal route, which binds no groupName
	}{
		{http.MethodPost, "/api/v1/groups/resolve", ""},
		{http.MethodPost, "/api/v1/groups/add-member", ""},
		{http.MethodPost, "/api/v1/groups/remove-member", ""},
		{http.MethodGet, "/api/v1/groups/Domain Admins", "Domain Admins"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.path, nil)
			if err != nil {
				t.Fatalf("failed to build request: %v", err)
			}

			var match mux.RouteMatch
			if !router.Match(req, &match) {
				t.Fatalf("%s %s matched no route", tt.method, tt.path)
			}
			if got := match.Vars["groupName"]; got != tt.wantVar {
				t.Errorf("groupName = %q, want %q", got, tt.wantVar)
			}
		})
	}
}

func TestGetLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := getLogLevel(tt.input)
			if got != tt.want {
				t.Errorf("getLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCertsExist(t *testing.T) {
	t.Run("nonexistent files return false", func(t *testing.T) {
		got := certsExist("/nonexistent/cert.pem", "/nonexistent/key.pem")
		if got {
			t.Error("certsExist() = true for nonexistent files, want false")
		}
	})

	t.Run("existing files return true", func(t *testing.T) {
		// go.mod and go.sum exist in the project root
		got := certsExist("go.mod", "go.sum")
		if !got {
			t.Error("certsExist() = false for existing files, want true")
		}
	})

	t.Run("one missing file returns false", func(t *testing.T) {
		got := certsExist("go.mod", "/nonexistent/key.pem")
		if got {
			t.Error("certsExist() = true when key file missing, want false")
		}
	})
}
