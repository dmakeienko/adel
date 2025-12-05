package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	Server  ServerConfig
	AD      ADConfig
	TLS     TLSConfig
	CORS    CORSConfig
	Logging LoggingConfig
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port         string
	Environment  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// ADConfig holds Active Directory configuration
type ADConfig struct {
	Server       string
	Port         int
	BaseDN       string
	UseSSL       bool
	SkipTLS      bool
	UserFilter   string
	GroupFilter  string
	SearchFilter string
	// Optional: Path to CA certificate for LDAPS
	CACertPath string
}

// TLSConfig holds TLS/HTTPS configuration
type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string
	Format string // "json" or "text"
	Debug  bool
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:         getEnv("PORT", "8443"),
			Environment:  getEnv("ENVIRONMENT", "development"),
			ReadTimeout:  getDurationEnv("READ_TIMEOUT", 60) * time.Second,
			WriteTimeout: getDurationEnv("WRITE_TIMEOUT", 60) * time.Second,
			IdleTimeout:  getDurationEnv("IDLE_TIMEOUT", 60) * time.Second,
		},
		AD: ADConfig{
			Server:       getEnv("AD_SERVER", ""),
			Port:         getIntEnv("AD_PORT", 389),
			BaseDN:       getEnv("AD_BASE_DN", ""),
			UseSSL:       getBoolEnv("AD_USE_SSL", false),
			SkipTLS:      getBoolEnv("AD_SKIP_TLS", false),
			UserFilter:   getEnv("AD_USER_FILTER", "(objectClass=user)"),
			GroupFilter:  getEnv("AD_GROUP_FILTER", "(objectClass=group)"),
			SearchFilter: getEnv("AD_SEARCH_FILTER", "(objectClass=*)"),
			CACertPath:   getEnv("AD_CA_CERT_PATH", ""),
		},
		TLS: TLSConfig{
			Enabled:  getBoolEnv("TLS_ENABLED", true),
			CertFile: getEnv("TLS_CERT_FILE", "certs/server.crt"),
			KeyFile:  getEnv("TLS_KEY_FILE", "certs/server.key"),
		},
		CORS: CORSConfig{
			AllowedOrigins:   getSliceEnv("CORS_ALLOWED_ORIGINS", []string{"*"}),
			AllowedMethods:   getSliceEnv("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}),
			AllowedHeaders:   getSliceEnv("CORS_ALLOWED_HEADERS", []string{"Accept", "Authorization", "Content-Type", "X-Session-ID"}),
			AllowCredentials: getBoolEnv("CORS_ALLOW_CREDENTIALS", true),
			MaxAge:           getIntEnv("CORS_MAX_AGE", 86400),
		},
		Logging: LoggingConfig{
			Level:  getEnv("LOG_LEVEL", "info"),
			Format: getEnv("LOG_FORMAT", "json"),
			Debug:  getEnv("LOG_LEVEL", "info") == "debug",
		},
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.AD.Server == "" {
		return fmt.Errorf("AD_SERVER is required")
	}
	if c.AD.BaseDN == "" {
		return fmt.Errorf("AD_BASE_DN is required")
	}
	return nil
}

// GetLDAPURL returns the LDAP connection URL
func (c *Config) GetLDAPURL() string {
	protocol := "ldap"
	if c.AD.UseSSL {
		protocol = "ldaps"
	}
	return fmt.Sprintf("%s://%s:%d", protocol, c.AD.Server, c.AD.Port)
}

// getEnv gets environment variable with default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getIntEnv gets integer environment variable with default value
func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getBoolEnv gets boolean environment variable with default value
func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// getDurationEnv gets duration environment variable with default value (in seconds)
func getDurationEnv(key string, defaultValue int) time.Duration {
	return time.Duration(getIntEnv(key, defaultValue))
}

// getSliceEnv gets slice environment variable with default value (comma-separated)
func getSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Split by comma and trim spaces
		var result []string
		for _, item := range splitAndTrim(value, ",") {
			if item != "" {
				result = append(result, item)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}

// splitAndTrim splits a string by delimiter and trims spaces
func splitAndTrim(s string, delimiter string) []string {
	var result []string
	for _, item := range splitString(s, delimiter) {
		trimmed := trimSpace(item)
		result = append(result, trimmed)
	}
	return result
}

// splitString splits a string by delimiter
func splitString(s string, delimiter string) []string {
	if s == "" {
		return []string{}
	}
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if i+len(delimiter) <= len(s) && s[i:i+len(delimiter)] == delimiter {
			result = append(result, current)
			current = ""
			i += len(delimiter) - 1
		} else {
			current += string(s[i])
		}
	}
	result = append(result, current)
	return result
}

// trimSpace removes leading and trailing spaces
func trimSpace(s string) string {
	start := 0
	end := len(s)

	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}
