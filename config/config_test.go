package config

import (
	"os"
	"strings"
	"testing"
)

func TestGetEnv(t *testing.T) {
	t.Run("returns default when env not set", func(t *testing.T) {
		got := getEnv("TEST_UNSET_VAR_12345", "default")
		if got != "default" {
			t.Errorf("getEnv() = %q, want %q", got, "default")
		}
	})

	t.Run("returns env value when set", func(t *testing.T) {
		os.Setenv("TEST_GET_ENV", "myvalue")
		defer os.Unsetenv("TEST_GET_ENV")

		got := getEnv("TEST_GET_ENV", "default")
		if got != "myvalue" {
			t.Errorf("getEnv() = %q, want %q", got, "myvalue")
		}
	})
}

func TestGetIntEnv(t *testing.T) {
	t.Run("returns default when env not set", func(t *testing.T) {
		got := getIntEnv("TEST_UNSET_INT", 42)
		if got != 42 {
			t.Errorf("getIntEnv() = %d, want %d", got, 42)
		}
	})

	t.Run("returns parsed int", func(t *testing.T) {
		os.Setenv("TEST_INT_ENV", "100")
		defer os.Unsetenv("TEST_INT_ENV")

		got := getIntEnv("TEST_INT_ENV", 42)
		if got != 100 {
			t.Errorf("getIntEnv() = %d, want %d", got, 100)
		}
	})

	t.Run("returns default on invalid int", func(t *testing.T) {
		os.Setenv("TEST_INT_ENV_BAD", "notanumber")
		defer os.Unsetenv("TEST_INT_ENV_BAD")

		got := getIntEnv("TEST_INT_ENV_BAD", 42)
		if got != 42 {
			t.Errorf("getIntEnv() = %d, want %d", got, 42)
		}
	})
}

func TestGetBoolEnv(t *testing.T) {
	t.Run("returns default when env not set", func(t *testing.T) {
		got := getBoolEnv("TEST_UNSET_BOOL", true)
		if got != true {
			t.Errorf("getBoolEnv() = %v, want %v", got, true)
		}
	})

	t.Run("returns parsed bool true", func(t *testing.T) {
		os.Setenv("TEST_BOOL_ENV", "true")
		defer os.Unsetenv("TEST_BOOL_ENV")

		got := getBoolEnv("TEST_BOOL_ENV", false)
		if got != true {
			t.Errorf("getBoolEnv() = %v, want %v", got, true)
		}
	})

	t.Run("returns parsed bool false", func(t *testing.T) {
		os.Setenv("TEST_BOOL_ENV2", "false")
		defer os.Unsetenv("TEST_BOOL_ENV2")

		got := getBoolEnv("TEST_BOOL_ENV2", true)
		if got != false {
			t.Errorf("getBoolEnv() = %v, want %v", got, false)
		}
	})

	t.Run("returns default on invalid bool", func(t *testing.T) {
		os.Setenv("TEST_BOOL_ENV_BAD", "notabool")
		defer os.Unsetenv("TEST_BOOL_ENV_BAD")

		got := getBoolEnv("TEST_BOOL_ENV_BAD", true)
		if got != true {
			t.Errorf("getBoolEnv() = %v, want %v", got, true)
		}
	})
}

func TestGetSliceEnv(t *testing.T) {
	t.Run("returns default when env not set", func(t *testing.T) {
		def := []string{"a", "b"}
		got := getSliceEnv("TEST_UNSET_SLICE", def)
		if len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Errorf("getSliceEnv() = %v, want %v", got, def)
		}
	})

	t.Run("returns parsed slice", func(t *testing.T) {
		os.Setenv("TEST_SLICE_ENV", "x, y, z")
		defer os.Unsetenv("TEST_SLICE_ENV")

		got := getSliceEnv("TEST_SLICE_ENV", nil)
		if len(got) != 3 || got[0] != "x" || got[1] != "y" || got[2] != "z" {
			t.Errorf("getSliceEnv() = %v, want [x y z]", got)
		}
	})
}

func TestGetDNSliceEnv(t *testing.T) {
	t.Setenv("TEST_DN_SLICE_ENV", "Helpdesk; CN=Directory Admins,OU=Groups,DC=example,DC=com ; ")

	got := getDNSliceEnv("TEST_DN_SLICE_ENV", nil)
	want := []string{"Helpdesk", "CN=Directory Admins,OU=Groups,DC=example,DC=com"} //nolint:goconst // test fixture data
	if len(got) != len(want) {
		t.Fatalf("getDNSliceEnv() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("getDNSliceEnv()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		delimiter string
		want      []string
	}{
		{"empty string", "", ",", []string{}},
		{"single element", "hello", ",", []string{"hello"}}, //nolint:goconst // test fixture data
		{"multiple elements", "a,b,c", ",", []string{"a", "b", "c"}},
		{"multi-char delimiter", "a::b::c", "::", []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitString(tt.input, tt.delimiter)
			if len(got) != len(tt.want) {
				t.Errorf("splitString() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitString()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"  hello  ", "hello"},
		{"\t\nhello\r\n", "hello"},
		{"hello", "hello"},
		{"  ", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := trimSpace(tt.input)
			if got != tt.want {
				t.Errorf("trimSpace(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &Config{
			AD: ADConfig{Server: "ad.example.com", BaseDN: "dc=example,dc=com"}, //nolint:goconst // test fixture data
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("missing AD_SERVER", func(t *testing.T) {
		cfg := &Config{
			AD: ADConfig{BaseDN: "dc=example,dc=com"},
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() error = nil, want error for missing AD_SERVER")
		}
	})

	t.Run("missing AD_BASE_DN", func(t *testing.T) {
		cfg := &Config{
			AD: ADConfig{Server: "ad.example.com"},
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() error = nil, want error for missing AD_BASE_DN")
		}
	})
}

func TestGetLDAPURL(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{
			"ldap url",
			Config{AD: ADConfig{Server: "ad.example.com", Port: 389, UseSSL: false}},
			"ldap://ad.example.com:389",
		},
		{
			"ldaps url",
			Config{AD: ADConfig{Server: "ad.example.com", Port: 636, UseSSL: true}},
			"ldaps://ad.example.com:636",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetLDAPURL()
			if got != tt.want {
				t.Errorf("GetLDAPURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	// Set required env vars
	os.Setenv("AD_SERVER", "test-ad.example.com")
	os.Setenv("AD_BASE_DN", "dc=test,dc=com")
	os.Setenv("AD_SEARCH_ALLOWED_GROUPS", "Helpdesk;Directory Admins")
	os.Setenv("AD_PASSWORD_RESET_ALLOWED_GROUPS", "Service Desk;Directory Admins")
	defer os.Unsetenv("AD_SERVER")
	defer os.Unsetenv("AD_BASE_DN")
	defer os.Unsetenv("AD_SEARCH_ALLOWED_GROUPS")
	defer os.Unsetenv("AD_PASSWORD_RESET_ALLOWED_GROUPS")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.AD.Server != "test-ad.example.com" {
		t.Errorf("AD.Server = %q, want %q", cfg.AD.Server, "test-ad.example.com")
	}
	if cfg.Server.Port != "8080" {
		t.Errorf("Server.Port = %q, want %q", cfg.Server.Port, "8080")
	}
	if len(cfg.AD.SearchAllowedGroups) != 2 || cfg.AD.SearchAllowedGroups[0] != "Helpdesk" || cfg.AD.SearchAllowedGroups[1] != "Directory Admins" {
		t.Errorf("AD.SearchAllowedGroups = %v, want [Helpdesk Directory Admins]", cfg.AD.SearchAllowedGroups)
	}
	if len(cfg.AD.PasswordResetAllowedGroups) != 2 || cfg.AD.PasswordResetAllowedGroups[0] != "Service Desk" {
		t.Errorf("AD.PasswordResetAllowedGroups = %v, want [Service Desk Directory Admins]", cfg.AD.PasswordResetAllowedGroups)
	}
}

func TestCanResetPasswordFor(t *testing.T) {
	tests := []struct {
		name          string
		memberOf      []string
		allowedGroups []string
		want          bool
	}{
		{name: "empty allow-list disables reset", memberOf: []string{dnHelpdesk}, want: false},
		{name: "matches bare CN", memberOf: []string{dnHelpdesk}, allowedGroups: []string{"helpdesk"}, want: true},
		{name: "matches full DN", memberOf: []string{dnHelpdesk}, allowedGroups: []string{"cn=helpdesk,ou=groups,dc=example,dc=com"}, want: true},
		{name: "matches nested membership", memberOf: []string{dnEmployees, dnHelpdesk}, allowedGroups: []string{"Helpdesk"}, want: true},
		{name: "rejects another group", memberOf: []string{dnEmployees}, allowedGroups: []string{"Helpdesk"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ADConfig{PasswordResetAllowedGroups: tt.allowedGroups}
			if got := cfg.CanResetPasswordFor(tt.memberOf); got != tt.want {
				t.Errorf("CanResetPasswordFor(%v) = %v, want %v", tt.memberOf, got, tt.want)
			}
		})
	}
}

func TestIsSearchAllowedFor(t *testing.T) {
	tests := []struct {
		name          string
		memberOf      []string
		allowedGroups []string
		want          bool
	}{
		{
			name: "empty allow-list permits authenticated users",
			want: true,
		},
		{
			name:          "matches group CN case-insensitively",
			memberOf:      []string{dnHelpdesk},
			allowedGroups: []string{"helpdesk"},
			want:          true,
		},
		{
			name:          "matches full DN case-insensitively",
			memberOf:      []string{"CN=Directory Admins,OU=Groups,DC=example,DC=com"},
			allowedGroups: []string{"cn=directory admins,ou=groups,dc=example,dc=com"},
			want:          true,
		},
		{
			name:          "handles escaped group CN",
			memberOf:      []string{`CN=Support\, Tier 2,OU=Groups,DC=example,DC=com`},
			allowedGroups: []string{"Support, Tier 2"},
			want:          true,
		},
		{
			name:          "matches a group reached through nesting",
			memberOf:      []string{"CN=Helpdesk-Tier1,OU=Groups,DC=example,DC=com", dnHelpdesk},
			allowedGroups: []string{"Helpdesk"},
			want:          true,
		},
		{
			name:          "rejects users outside allowed groups",
			memberOf:      []string{dnEmployees},
			allowedGroups: []string{"Helpdesk", "Directory Admins"},
			want:          false,
		},
		{
			name:          "rejects users with unknown memberships",
			allowedGroups: []string{"Helpdesk"},
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ADConfig{SearchAllowedGroups: tt.allowedGroups}
			if got := c.IsSearchAllowedFor(tt.memberOf); got != tt.want {
				t.Errorf("IsSearchAllowedFor(%v) with allowed %v = %v, want %v",
					tt.memberOf, tt.allowedGroups, got, tt.want)
			}
		})
	}
}

// Shared DN fixtures, so the expected derivations read against a single spelling.
const (
	dnHelpdesk        = "CN=Helpdesk,OU=Groups,DC=example,DC=com"
	dnEngineeringLead = "CN=engineering-lead,OU=Groups,DC=example,DC=com"
	dnEmployees       = "CN=Employees,OU=Groups,DC=example,DC=com"
	wildcardEngineer  = "CN=engineering-*"
)

// enabledLeadConfig is a config with lead detection switched on, as an operator would
// after setting AD_LEAD_GROUP_SUFFIXES. Lead detection is off unless configured, so
// tests must opt in explicitly rather than relying on a default.
func enabledLeadConfig() *ADConfig {
	return &ADConfig{
		LeadGroupSuffixes: []string{"-lead", "-pm"},
		LeadGroupWildcard: "-*",
	}
}

func TestLeadGroupsFor(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *ADConfig
		memberOf []string
		want     []string
	}{
		{
			name:     "derives wildcard identifier from a lead group",
			cfg:      enabledLeadConfig(),
			memberOf: []string{dnEngineeringLead},
			want:     []string{wildcardEngineer},
		},
		{
			name:     "derives wildcard identifier from a pm group",
			cfg:      enabledLeadConfig(),
			memberOf: []string{"CN=engineering-pm,OU=Groups,DC=example,DC=com"},
			want:     []string{wildcardEngineer},
		},
		{
			name: "collapses lead and pm of the same base group",
			cfg:  enabledLeadConfig(),
			memberOf: []string{
				dnEngineeringLead,
				"CN=engineering-pm,OU=Other,DC=example,DC=com",
			},
			want: []string{wildcardEngineer},
		},
		{
			name: "matches suffixes case-insensitively",
			cfg:  enabledLeadConfig(),
			memberOf: []string{
				"CN=Engineering-LEAD,OU=Groups,DC=example,DC=com",
				"CN=Support-Pm,OU=Groups,DC=example,DC=com",
			},
			want: []string{"CN=Engineering-*", "CN=Support-*"},
		},
		{
			name:     "excludes groups without a role suffix",
			cfg:      enabledLeadConfig(),
			memberOf: []string{dnEmployees},
			want:     nil,
		},
		{
			name: "ignores suffixes appearing only in OU or DC components",
			cfg:  enabledLeadConfig(),
			memberOf: []string{
				"CN=Employees,OU=engineering-lead,DC=example,DC=com",
				"CN=Employees,OU=Groups,DC=corp-pm,DC=com",
			},
			want: nil,
		},
		{
			name: "skips malformed DNs and keeps processing the rest",
			cfg:  enabledLeadConfig(),
			memberOf: []string{
				"not a dn",
				"",
				dnEngineeringLead,
			},
			want: []string{wildcardEngineer},
		},
		{
			name:     "keeps a CN that is only the suffix out of the results",
			cfg:      enabledLeadConfig(),
			memberOf: []string{"CN=-lead,OU=Groups,DC=example,DC=com"},
			want:     nil,
		},
		{
			name:     "honours custom suffixes",
			cfg:      &ADConfig{LeadGroupSuffixes: []string{"-owner"}, LeadGroupWildcard: "-*"},
			memberOf: []string{"CN=payments-owner,OU=Groups,DC=example,DC=com", "CN=payments-lead,OU=Groups,DC=example,DC=com"},
			want:     []string{"CN=payments-*"},
		},
		{
			name:     "honours a custom wildcard",
			cfg:      &ADConfig{LeadGroupSuffixes: []string{"-lead"}, LeadGroupWildcard: "-all"},
			memberOf: []string{dnEngineeringLead},
			want:     []string{"CN=engineering-all"},
		},
		{
			name:     "disabled when no suffixes are configured",
			cfg:      &ADConfig{LeadGroupWildcard: "-*"},
			memberOf: []string{dnEngineeringLead},
			want:     nil,
		},
		{
			name: "preserves an escaped comma in the CN",
			cfg:  enabledLeadConfig(),
			memberOf: []string{
				`CN=Support\, Tier 2-lead,OU=Groups,DC=example,DC=com`,
			},
			want: []string{"CN=Support, Tier 2-*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.LeadGroupsFor(tt.memberOf)
			if len(got) != len(tt.want) {
				t.Fatalf("LeadGroupsFor(%v) = %v, want %v", tt.memberOf, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("LeadGroupsFor(%v)[%d] = %q, want %q", tt.memberOf, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestLeadDetectionDisabledByDefault pins the opt-in contract: without
// AD_LEAD_GROUP_SUFFIXES the feature is completely inert, so a directory that happens to
// use "-lead" naming does not silently acquire leads with scoped search access.
func TestLeadDetectionDisabledByDefault(t *testing.T) {
	os.Setenv("AD_SERVER", "test-ad.example.com")
	os.Setenv("AD_BASE_DN", "dc=test,dc=com")
	os.Setenv("AD_SEARCH_ALLOWED_GROUPS", "Helpdesk")
	defer os.Unsetenv("AD_SERVER")
	defer os.Unsetenv("AD_BASE_DN")
	defer os.Unsetenv("AD_SEARCH_ALLOWED_GROUPS")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.AD.LeadGroupSuffixes) != 0 {
		t.Errorf("LeadGroupSuffixes = %v, want empty by default", cfg.AD.LeadGroupSuffixes)
	}

	lead := []string{dnEngineeringLead}
	if cfg.AD.IsLeadFor(lead) {
		t.Error("membership of a -lead group must not confer a role when the feature is off")
	}
	if got := cfg.AD.LeadGroupsFor(lead); len(got) != 0 {
		t.Errorf("LeadGroupsFor() = %v, want none when the feature is off", got)
	}
	if got := cfg.AD.LeadGroupCNFilter(lead); got != "" {
		t.Errorf("LeadGroupCNFilter() = %q, want empty when the feature is off", got)
	}
	// With the allow-list set and lead detection off, a -lead member is simply denied
	// rather than silently getting scoped access.
	if got := cfg.AD.AccessFor(lead); got != SearchDenied {
		t.Errorf("AccessFor() = %v, want SearchDenied when the feature is off", got)
	}
}

// TestLeadDetectionEnabledByEnv confirms setting the env var turns the feature on.
func TestLeadDetectionEnabledByEnv(t *testing.T) {
	os.Setenv("AD_SERVER", "test-ad.example.com")
	os.Setenv("AD_BASE_DN", "dc=test,dc=com")
	os.Setenv("AD_LEAD_GROUP_SUFFIXES", "-lead,-pm")
	defer os.Unsetenv("AD_SERVER")
	defer os.Unsetenv("AD_BASE_DN")
	defer os.Unsetenv("AD_LEAD_GROUP_SUFFIXES")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.AD.IsLeadFor([]string{dnEngineeringLead}) {
		t.Error("a -lead member should hold a role once the suffixes are configured")
	}
	if got := cfg.AD.LeadGroupsFor([]string{dnEngineeringLead}); len(got) != 1 || got[0] != wildcardEngineer {
		t.Errorf("LeadGroupsFor() = %v, want [%s]", got, wildcardEngineer)
	}
}

func TestAccessFor(t *testing.T) {
	withAllowList := enabledLeadConfig()
	withAllowList.SearchAllowedGroups = []string{"Helpdesk"}

	tests := []struct {
		name     string
		cfg      *ADConfig
		memberOf []string
		want     SearchAccess
	}{
		{
			name:     "empty allow-list leaves everyone unrestricted",
			cfg:      enabledLeadConfig(),
			memberOf: []string{dnEmployees},
			want:     SearchUnrestricted,
		},
		{
			name:     "allow-listed user is unrestricted",
			cfg:      withAllowList,
			memberOf: []string{dnHelpdesk},
			want:     SearchUnrestricted,
		},
		{
			name:     "lead is scoped rather than unrestricted",
			cfg:      withAllowList,
			memberOf: []string{dnEngineeringLead},
			want:     SearchScoped,
		},
		{
			name:     "pm is scoped",
			cfg:      withAllowList,
			memberOf: []string{"CN=engineering-pm,OU=Groups,DC=example,DC=com"},
			want:     SearchScoped,
		},
		{
			name:     "allow-list wins over lead role",
			cfg:      withAllowList,
			memberOf: []string{dnEngineeringLead, dnHelpdesk},
			want:     SearchUnrestricted,
		},
		{
			name:     "plain member is denied",
			cfg:      withAllowList,
			memberOf: []string{dnEmployees},
			want:     SearchDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.AccessFor(tt.memberOf); got != tt.want {
				t.Errorf("AccessFor(%v) = %v, want %v", tt.memberOf, got, tt.want)
			}
		})
	}
}

func TestLeadGroupCNFilter(t *testing.T) {
	cfg := enabledLeadConfig()

	t.Run("matches the base name as a prefix wildcard", func(t *testing.T) {
		got := cfg.LeadGroupCNFilter([]string{dnEngineeringLead})
		want := "(cn=engineering*)"
		if got != want {
			t.Errorf("LeadGroupCNFilter() = %q, want %q", got, want)
		}
	})

	t.Run("ORs multiple bases", func(t *testing.T) {
		got := cfg.LeadGroupCNFilter([]string{
			dnEngineeringLead,
			"CN=support-pm,OU=Groups,DC=example,DC=com",
		})
		want := "(|(cn=engineering*)(cn=support*))"
		if got != want {
			t.Errorf("LeadGroupCNFilter() = %q, want %q", got, want)
		}
	})

	t.Run("empty for a non-lead so callers match nothing", func(t *testing.T) {
		if got := cfg.LeadGroupCNFilter([]string{dnEmployees}); got != "" {
			t.Errorf("LeadGroupCNFilter() = %q, want empty", got)
		}
	})

	t.Run("escapes filter metacharacters in the base name", func(t *testing.T) {
		got := cfg.LeadGroupCNFilter([]string{`CN=a)(b-lead,OU=Groups,DC=example,DC=com`})
		if strings.Contains(got, "a)(b") {
			t.Errorf("LeadGroupCNFilter() = %q, want the base name escaped", got)
		}
	})
}

func TestLeadScopeFilter(t *testing.T) {
	t.Run("matches members of one group", func(t *testing.T) {
		got := LeadScopeFilter([]string{"CN=engineering,OU=Groups,DC=example,DC=com"})
		want := "(memberOf=CN=engineering,OU=Groups,DC=example,DC=com)"
		if got != want {
			t.Errorf("LeadScopeFilter() = %q, want %q", got, want)
		}
	})

	t.Run("ORs multiple groups", func(t *testing.T) {
		got := LeadScopeFilter([]string{"CN=a,DC=x", "CN=b,DC=x"})
		want := "(|(memberOf=CN=a,DC=x)(memberOf=CN=b,DC=x))"
		if got != want {
			t.Errorf("LeadScopeFilter() = %q, want %q", got, want)
		}
	})

	t.Run("empty scope yields empty filter, never a match-all", func(t *testing.T) {
		if got := LeadScopeFilter(nil); got != "" {
			t.Errorf("LeadScopeFilter(nil) = %q, want empty", got)
		}
	})
}

func TestIsGroupInLeadScope(t *testing.T) {
	cfg := enabledLeadConfig()
	lead := []string{dnEngineeringLead}

	inScope := []string{"engineering", "engineering-devs", "Engineering-QA", "engineering-lead"}
	for _, cn := range inScope {
		if !cfg.IsGroupInLeadScope(lead, cn) {
			t.Errorf("IsGroupInLeadScope(%q) = false, want true", cn)
		}
	}

	outOfScope := []string{"finance", "finance-team", "eng", "core-engineering"}
	for _, cn := range outOfScope {
		if cfg.IsGroupInLeadScope(lead, cn) {
			t.Errorf("IsGroupInLeadScope(%q) = true, want false", cn)
		}
	}

	if cfg.IsGroupInLeadScope([]string{dnEmployees}, "engineering") {
		t.Error("a non-lead should have an empty scope matching nothing")
	}
}
