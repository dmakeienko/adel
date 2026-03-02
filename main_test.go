package main

import (
	"log/slog"
	"testing"
)

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
