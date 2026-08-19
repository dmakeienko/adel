package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
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
	// SearchBaseDN restricts searches to a specific OU (e.g. "OU=Corp,DC=example,DC=com").
	// If empty, BaseDN is used.
	SearchBaseDN string
	// ExcludedObjects is a list of DN path fragments (OUs, CNs, etc.) whose entries are filtered out of results.
	ExcludedObjects []string
	// ExcludedGroups is a list of group CNs or DNs that are filtered out of group results.
	ExcludedGroups []string
	// MaxSearchResults caps the number of entries any single LDAP search may return.
	// It is passed as the LDAP size limit, so the directory stops sending at the cap
	// rather than the server discarding a large result after transferring it.
	MaxSearchResults int
	// SearchAllowedGroups is a list of group CNs or DNs whose members may use the search endpoint.
	// If empty, search is available to every authenticated user.
	SearchAllowedGroups []string
	// PasswordResetAllowedGroups is a list of group CNs or DNs whose members may
	// reset another user's password. Empty disables password resets.
	PasswordResetAllowedGroups []string
	// LeadGroupSuffixes are the CN suffixes marking a role-bearing group, e.g. "-lead"
	// and "-pm". A user in such a group is a lead/PM of the base group named by the CN
	// with the suffix replaced by LeadGroupWildcard.
	//
	// Empty by default: lead detection is opt-in and stays completely inert until
	// AD_LEAD_GROUP_SUFFIXES is set, so a directory that happens to use "-lead" naming
	// does not silently acquire leads.
	LeadGroupSuffixes []string
	// LeadGroupWildcard replaces a matched suffix when deriving the base-group
	// identifier: "engineering-lead" becomes "engineering-*". Only consulted when
	// LeadGroupSuffixes is non-empty.
	LeadGroupWildcard string
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
			Port:         getEnv("PORT", "8080"),
			Environment:  getEnv("ENVIRONMENT", "development"),
			ReadTimeout:  getDurationEnv("READ_TIMEOUT", 60) * time.Second,
			WriteTimeout: getDurationEnv("WRITE_TIMEOUT", 60) * time.Second,
			IdleTimeout:  getDurationEnv("IDLE_TIMEOUT", 60) * time.Second,
		},
		AD: ADConfig{
			Server:                     getEnv("AD_SERVER", ""),
			Port:                       getIntEnv("AD_PORT", 389),
			BaseDN:                     getEnv("AD_BASE_DN", ""),
			UseSSL:                     getBoolEnv("AD_USE_SSL", false),
			SkipTLS:                    getBoolEnv("AD_SKIP_TLS", false),
			UserFilter:                 getEnv("AD_USER_FILTER", "(objectClass=user)"),
			GroupFilter:                getEnv("AD_GROUP_FILTER", "(objectClass=group)"),
			SearchFilter:               getEnv("AD_SEARCH_FILTER", "(objectClass=*)"),
			SearchBaseDN:               getEnv("AD_SEARCH_BASE_DN", ""),
			ExcludedObjects:            getDNSliceEnv("AD_EXCLUDED_OBJECTS", nil),
			MaxSearchResults:           getIntEnv("AD_MAX_SEARCH_RESULTS", 200),
			ExcludedGroups:             getDNSliceEnv("AD_EXCLUDED_GROUPS", nil),
			SearchAllowedGroups:        getDNSliceEnv("AD_SEARCH_ALLOWED_GROUPS", nil),
			PasswordResetAllowedGroups: getDNSliceEnv("AD_PASSWORD_RESET_ALLOWED_GROUPS", nil),
			LeadGroupSuffixes:          getSliceEnv("AD_LEAD_GROUP_SUFFIXES", nil),
			LeadGroupWildcard:          getEnv("AD_LEAD_GROUP_WILDCARD", "-*"),
			CACertPath:                 getEnv("AD_CA_CERT_PATH", ""),
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

// GetSearchBaseDN returns SearchBaseDN if set, otherwise falls back to BaseDN.
func (c *ADConfig) GetSearchBaseDN() string {
	if c.SearchBaseDN != "" {
		return c.SearchBaseDN
	}
	return c.BaseDN
}

// SearchAccess describes how much of the directory a user may see.
type SearchAccess int

const (
	// SearchDenied means the user may not use the browsing endpoints at all.
	SearchDenied SearchAccess = iota
	// SearchScoped means the user may search, but only within the groups they lead.
	// Callers must apply LeadScopeFilter to every search they run for such a user.
	SearchScoped
	// SearchUnrestricted means the user may search the whole configured base DN.
	SearchUnrestricted
)

// AccessFor reports how much of the directory a user holding the given group DNs may
// see. The allow-list grants unrestricted access and takes precedence, so an admin who
// also happens to lead a team is not accidentally narrowed to it. Otherwise a lead or
// PM gets access scoped to the groups they lead, and everyone else is denied.
//
// An empty allow-list preserves the historical default of unrestricted access for every
// authenticated user, so enabling lead scoping requires setting AD_SEARCH_ALLOWED_GROUPS.
func (c *ADConfig) AccessFor(memberOf []string) SearchAccess {
	if len(c.SearchAllowedGroups) == 0 {
		return SearchUnrestricted
	}

	if c.isAllowListed(memberOf) {
		return SearchUnrestricted
	}

	if c.IsLeadFor(memberOf) {
		return SearchScoped
	}

	return SearchDenied
}

// IsSearchAllowedFor reports whether a user may use the search endpoint in any capacity.
// It does not distinguish scoped from unrestricted access: callers that run a directory
// search must consult AccessFor and apply LeadScopeFilter when the result is SearchScoped.
func (c *ADConfig) IsSearchAllowedFor(memberOf []string) bool {
	return c.AccessFor(memberOf) != SearchDenied
}

// isAllowListed reports whether any of the user's groups appears in SearchAllowedGroups,
// matched either as a full DN or as a bare CN.
func (c *ADConfig) isAllowListed(memberOf []string) bool {
	return isMemberOfAnyGroup(memberOf, c.SearchAllowedGroups)
}

// CanResetPasswordFor reports whether a user may use the privileged password-reset
// endpoint. Unlike search access, an empty allow-list disables the feature.
func (c *ADConfig) CanResetPasswordFor(memberOf []string) bool {
	return len(c.PasswordResetAllowedGroups) > 0 &&
		isMemberOfAnyGroup(memberOf, c.PasswordResetAllowedGroups)
}

// isMemberOfAnyGroup matches configured groups by full DN or bare CN,
// case-insensitively. memberOf includes nested memberships resolved at login.
func isMemberOfAnyGroup(memberOf, allowedGroups []string) bool {
	for _, groupDN := range memberOf {
		for _, allowedGroup := range allowedGroups {
			if strings.EqualFold(groupDN, allowedGroup) {
				return true
			}
		}

		cn, ok := GroupCN(groupDN)
		if !ok {
			continue
		}
		for _, allowedGroup := range allowedGroups {
			if !strings.Contains(allowedGroup, "=") && strings.EqualFold(cn, allowedGroup) {
				return true
			}
		}
	}

	return false
}

// GroupCN extracts the CN value from a group DN. Only the leftmost RDN is considered,
// so OU and DC components never take part in CN matching. The second return value is
// false when the DN is malformed or carries no CN, letting callers skip it safely.
func GroupCN(groupDN string) (string, bool) {
	parsedDN, err := ldap.ParseDN(groupDN)
	if err != nil || len(parsedDN.RDNs) == 0 {
		return "", false
	}
	for _, attribute := range parsedDN.RDNs[0].Attributes {
		if strings.EqualFold(attribute.Type, "CN") {
			return attribute.Value, true
		}
	}
	return "", false
}

// LeadBasesFor returns the bare base-group names the user leads, e.g. "engineering" for
// membership of "engineering-lead" or "engineering-pm". These are the raw names behind
// the wildcard identifiers, and are what the scope filters match on.
//
// Matching is case-insensitive and confined to the CN. Groups without a configured
// suffix, and DNs that cannot be parsed, are skipped — they remain ordinary memberships.
// The result is de-duplicated and returned in first-seen order for stable output.
func (c *ADConfig) LeadBasesFor(memberOf []string) []string {
	if len(c.LeadGroupSuffixes) == 0 {
		return nil
	}

	var bases []string
	seen := make(map[string]struct{}, len(memberOf))

	for _, groupDN := range memberOf {
		cn, ok := GroupCN(groupDN)
		if !ok {
			continue
		}

		for _, suffix := range c.LeadGroupSuffixes {
			if suffix == "" || !strings.HasSuffix(strings.ToLower(cn), strings.ToLower(suffix)) {
				continue
			}
			// A CN that is nothing but the suffix has no base group to name.
			base := cn[:len(cn)-len(suffix)]
			if base == "" {
				break
			}

			key := strings.ToLower(base)
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				bases = append(bases, base)
			}
			// Stop at the first matching suffix: suffixes are alternatives, and a CN
			// ending in two of them would otherwise yield two entries.
			break
		}
	}

	return bases
}

// LeadGroupsFor derives the wildcard base-group identifiers for the groups in which the
// user holds a lead or PM role, so both "engineering-lead" and "engineering-pm" collapse
// to the single identifier "CN=engineering-*". These are display identifiers reported to
// the UI; enforcement uses LeadScopeFilter, which is built from the same bases.
func (c *ADConfig) LeadGroupsFor(memberOf []string) []string {
	bases := c.LeadBasesFor(memberOf)
	if len(bases) == 0 {
		return nil
	}

	identifiers := make([]string, 0, len(bases))
	for _, base := range bases {
		identifiers = append(identifiers, "CN="+base+c.LeadGroupWildcard)
	}
	return identifiers
}

// IsLeadFor reports whether the user holds a lead or PM role in at least one group.
func (c *ADConfig) IsLeadFor(memberOf []string) bool {
	return len(c.LeadBasesFor(memberOf)) > 0
}

// LeadGroupCNFilter builds an LDAP filter matching the groups a lead may see: every
// group whose CN starts with one of their base names. This is the wildcard rendered as
// a filter, so "engineering-*" matches "engineering", "engineering-devs" and so on.
//
// Returns "" when the user leads nothing, which callers must treat as "match nothing"
// rather than "match everything".
func (c *ADConfig) LeadGroupCNFilter(memberOf []string) string {
	bases := c.LeadBasesFor(memberOf)
	if len(bases) == 0 {
		return ""
	}

	var clauses strings.Builder
	for _, base := range bases {
		// The base is directory data, so it is escaped; the trailing * stays literal so
		// it keeps its wildcard meaning.
		clauses.WriteString("(cn=" + ldap.EscapeFilter(base) + "*)")
	}

	if len(bases) == 1 {
		return clauses.String()
	}
	return "(|" + clauses.String() + ")"
}

// IsGroupInLeadScope reports whether a group CN falls within the caller's lead scope,
// i.e. whether it starts with one of their base names. It mirrors LeadGroupCNFilter so
// the in-process check and the LDAP-side filter agree on what "engineering-*" covers.
//
// A user who leads nothing has an empty scope and matches no group.
func (c *ADConfig) IsGroupInLeadScope(memberOf []string, groupCN string) bool {
	for _, base := range c.LeadBasesFor(memberOf) {
		if strings.HasPrefix(strings.ToLower(groupCN), strings.ToLower(base)) {
			return true
		}
	}
	return false
}

// LeadScopeFilter builds an LDAP filter matching the users a lead may see: members of
// any group within their wildcard scope. groupDNs are the in-scope group DNs, resolved
// by the caller via LeadGroupCNFilter, since membership must be tested against concrete
// DNs rather than names.
//
// Returns "" when there are no in-scope groups, which callers must treat as
// "match nothing" so an empty scope cannot silently widen into a full directory search.
func LeadScopeFilter(groupDNs []string) string {
	if len(groupDNs) == 0 {
		return ""
	}

	var clauses strings.Builder
	for _, dn := range groupDNs {
		// matchingRuleInChain would also catch users nested through subgroups, but it is
		// AD-specific; a direct memberOf test works on every directory and matches how
		// the rest of the group endpoints resolve membership.
		clauses.WriteString("(memberOf=" + ldap.EscapeFilter(dn) + ")")
	}

	if len(groupDNs) == 1 {
		return clauses.String()
	}
	return "(|" + clauses.String() + ")"
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

// getDNSliceEnv gets a semicolon-separated slice from an environment variable.
// Semicolons are used instead of commas because DN values contain commas
// (e.g. "OU=Disabled,DC=example,DC=com;OU=Service Accounts,DC=example,DC=com").
func getDNSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		var result []string
		for _, item := range splitAndTrim(value, ";") {
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
