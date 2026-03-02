package session

import (
	"testing"
)

func TestContainsAt(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"user@domain.com", true},
		{"username", false},
		{"", false},
		{"@", true},
		{"CN=user,DC=example", false},
	}

	for _, tt := range tests {
		got := containsAt(tt.input)
		if got != tt.want {
			t.Errorf("containsAt(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsDN(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"CN=John Doe,OU=Users,DC=example,DC=com", true},
		{"cn=john,dc=example", true},
		{"username", false},
		{"user@domain.com", false},
		{"", false},
		{"CN", false},
	}

	for _, tt := range tests {
		got := isDN(tt.input)
		if got != tt.want {
			t.Errorf("isDN(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestExtractDomainFromBaseDN(t *testing.T) {
	tests := []struct {
		name   string
		baseDN string
		want   string
	}{
		{"standard base DN", "dc=example,dc=com", "example.com"},
		{"uppercase DC", "DC=example,DC=com", "example.com"},
		{"three-level domain", "dc=sub,dc=example,dc=com", "sub.example.com"},
		{"empty string", "", ""},
		{"no DC components", "ou=Users,o=Company", ""},
		{"mixed case", "DC=Example,dc=Com", "Example.Com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomainFromBaseDN(tt.baseDN)
			if got != tt.want {
				t.Errorf("extractDomainFromBaseDN(%q) = %q, want %q", tt.baseDN, got, tt.want)
			}
		})
	}
}

func TestSplitDN(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			"standard DN",
			"CN=John Doe,OU=Users,DC=example,DC=com",
			[]string{"CN=John Doe", "OU=Users", "DC=example", "DC=com"},
		},
		{
			"escaped comma",
			`CN=Doe\, John,OU=Users,DC=example`,
			[]string{`CN=Doe\, John`, "OU=Users", "DC=example"},
		},
		{
			"empty string",
			"",
			nil,
		},
		{
			"single component",
			"DC=com",
			[]string{"DC=com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitDN(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("splitDN(%q) = %v (len %d), want %v (len %d)", tt.input, got, len(got), tt.want, len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitDN(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGenerateSessionID(t *testing.T) {
	id1, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID() error = %v", err)
	}

	if len(id1) != 64 {
		t.Errorf("session ID length = %d, want 64", len(id1))
	}

	// Ensure uniqueness
	id2, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID() error = %v", err)
	}

	if id1 == id2 {
		t.Error("two generated session IDs should not be equal")
	}
}
