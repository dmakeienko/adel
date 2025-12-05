package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"adel/session"
)

var (
	debugEnabled = false
)

// ContextKey is a custom type for context keys
type ContextKey string

const (
	// SessionContextKey is the context key for the session
	SessionContextKey ContextKey = "session"
)

// SetDebugLogging enables or disables debug logging
func SetDebugLogging(enabled bool) {
	debugEnabled = enabled
}

// debugLog logs a message only if debug logging is enabled
func debugLog(msg string, args ...interface{}) {
	if debugEnabled {
		slog.Debug(msg, args...)
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Logging middleware logs all HTTP requests
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapped, r)

		slog.Info("HTTP request",
			"remote_addr", r.RemoteAddr,
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration", time.Since(start).String(),
		)
	})
}

// Recovery middleware recovers from panics
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("Panic recovered",
					"error", err,
					"stack", string(debug.Stack()),
				)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CORSConfig holds CORS middleware configuration
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// CORS middleware handles Cross-Origin Resource Sharing
func CORS(config CORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			debugLog("CORS Request", "method", r.Method, "origin", origin, "path", r.URL.Path)
			debugLog("CORS Config AllowedOrigins", "origins", config.AllowedOrigins)

			// Check if origin is allowed
			allowed := false

			// If AllowedOrigins is empty or contains "*", allow all
			if len(config.AllowedOrigins) == 0 || contains(config.AllowedOrigins, "*") {
				allowed = true
				w.Header().Set("Access-Control-Allow-Origin", "*")
				debugLog("CORS: Allowing all origins (*)")
			} else if origin != "" {
				// Check if the specific origin is in the allowed list
				for _, o := range config.AllowedOrigins {
					if o == origin {
						allowed = true
						w.Header().Set("Access-Control-Allow-Origin", origin)
						debugLog("CORS: Origin allowed", "origin", origin)
						break
					}
				}
				if !allowed && origin != "" {
					debugLog("CORS: Origin NOT allowed", "origin", origin)
				}
			}

			// Only set other CORS headers if origin is allowed
			if allowed {
				// Set allowed methods
				if len(config.AllowedMethods) > 0 {
					w.Header().Set("Access-Control-Allow-Methods", joinStrings(config.AllowedMethods, ", "))
				}

				// Set allowed headers
				if len(config.AllowedHeaders) > 0 {
					w.Header().Set("Access-Control-Allow-Headers", joinStrings(config.AllowedHeaders, ", "))
				}

				// Set credentials
				if config.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				// Set max age
				if config.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", intToString(config.MaxAge))
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				if allowed {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireSession middleware ensures a valid session exists
func RequireSession(sessionMgr *session.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID := r.Header.Get("X-Session-ID")
			debugLog("RequireSession: Checking session", "method", r.Method, "path", r.URL.Path, "session_id", sessionID)

			if sessionID == "" {
				debugLog("RequireSession: Missing session ID", "method", r.Method, "path", r.URL.Path)
				http.Error(w, `{"success":false,"error":"Missing session ID"}`, http.StatusUnauthorized)
				return
			}

			sess, err := sessionMgr.GetSession(sessionID)
			if err != nil {
				debugLog("RequireSession: Invalid or expired session", "session_id", sessionID, "error", err)
				http.Error(w, `{"success":false,"error":"Invalid or expired session"}`, http.StatusUnauthorized)
				return
			}

			debugLog("RequireSession: Valid session found", "username", sess.Username)
			// Add session to context
			ctx := context.WithValue(r.Context(), SessionContextKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetSessionFromContext retrieves the session from context
func GetSessionFromContext(ctx context.Context) *session.Session {
	if sess, ok := ctx.Value(SessionContextKey).(*session.Session); ok {
		return sess
	}
	return nil
}

// ContentType middleware sets the Content-Type header
func ContentType(contentType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			next.ServeHTTP(w, r)
		})
	}
}

// JSON middleware sets Content-Type to application/json
func JSON(next http.Handler) http.Handler {
	return ContentType("application/json")(next)
}

// SecurityHeaders middleware adds security headers
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// Chain chains multiple middleware together
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// joinStrings joins a slice of strings with a separator
func joinStrings(slice []string, separator string) string {
	if len(slice) == 0 {
		return ""
	}
	result := slice[0]
	for i := 1; i < len(slice); i++ {
		result += separator + slice[i]
	}
	return result
}

// intToString converts an integer to a string
func intToString(n int) string {
	if n == 0 {
		return "0"
	}

	isNegative := n < 0
	if isNegative {
		n = -n
	}

	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}

	if isNegative {
		digits = append([]byte{'-'}, digits...)
	}

	return string(digits)
}
