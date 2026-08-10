package config

import (
	"os"
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
	defer os.Unsetenv("AD_SERVER")
	defer os.Unsetenv("AD_BASE_DN")
	defer os.Unsetenv("AD_SEARCH_ALLOWED_GROUPS")

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
			memberOf:      []string{"CN=Helpdesk,OU=Groups,DC=example,DC=com"},
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
			memberOf:      []string{"CN=Helpdesk-Tier1,OU=Groups,DC=example,DC=com", "CN=Helpdesk,OU=Groups,DC=example,DC=com"},
			allowedGroups: []string{"Helpdesk"},
			want:          true,
		},
		{
			name:          "rejects users outside allowed groups",
			memberOf:      []string{"CN=Employees,OU=Groups,DC=example,DC=com"},
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
