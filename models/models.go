package models

import "time"

// User represents an Active Directory user
type User struct {
	DN                 string            `json:"dn"`
	SAMAccountName     string            `json:"sAMAccountName"`
	UserPrincipalName  string            `json:"userPrincipalName,omitempty"`
	DisplayName        string            `json:"displayName,omitempty"`
	GivenName          string            `json:"givenName,omitempty"`
	Surname            string            `json:"sn,omitempty"`
	Email              string            `json:"mail,omitempty"`
	Department         string            `json:"department,omitempty"`
	Title              string            `json:"title,omitempty"`
	Manager            string            `json:"manager,omitempty"`
	MemberOf           []string          `json:"memberOf,omitempty"`
	Description        string            `json:"description,omitempty"`
	TelephoneNumber    string            `json:"telephoneNumber,omitempty"`
	Mobile             string            `json:"mobile,omitempty"`
	EmployeeID         string            `json:"employeeID,omitempty"`
	Company            string            `json:"company,omitempty"`
	StreetAddress      string            `json:"streetAddress,omitempty"`
	City               string            `json:"l,omitempty"`
	State              string            `json:"st,omitempty"`
	PostalCode         string            `json:"postalCode,omitempty"`
	Country            string            `json:"c,omitempty"`
	WhenCreated        string            `json:"whenCreated,omitempty"`
	WhenChanged        string            `json:"whenChanged,omitempty"`
	PwdLastSet         *time.Time        `json:"pwdLastSet,omitempty"`
	AccountExpires     *time.Time        `json:"accountExpires,omitempty"`
	Enabled            bool              `json:"enabled"`
	Attributes         map[string]string `json:"attributes,omitempty"`
	PasswordExpiryDate *time.Time        `json:"passwordExpiryDate,omitempty"`
}

// Group represents an Active Directory group
type Group struct {
	DN                string   `json:"dn"`
	CN                string   `json:"cn"`
	SAMAccountName    string   `json:"sAMAccountName"`
	Description       string   `json:"description,omitempty"`
	GroupType         string   `json:"groupType,omitempty"`
	Members           []string `json:"members,omitempty"`
	MemberOf          []string `json:"memberOf,omitempty"`
	DistinguishedName string   `json:"distinguishedName,omitempty"`
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	Success   bool   `json:"success"`
	SessionID string `json:"sessionId,omitempty"`
	Message   string `json:"message,omitempty"`
	User      *User  `json:"user,omitempty"`
}

// LogoutRequest represents the logout request body
type LogoutRequest struct {
	SessionID string `json:"sessionId"`
}

// GetUserRequest represents get user request
type GetUserRequest struct {
	Username string `json:"username"`
}

// EditUserRequest represents edit user request
type EditUserRequest struct {
	Username   string            `json:"username"`
	Attributes map[string]string `json:"attributes"`
}

// GroupMembershipRequest represents add/remove user from group request
type GroupMembershipRequest struct {
	Username  string `json:"username"`
	GroupName string `json:"groupName"`
}

// GetGroupsRequest represents get all groups request
type GetGroupsRequest struct {
	BaseDN string `json:"baseDN,omitempty"`
	Filter string `json:"filter,omitempty"`
}

// SearchRequest represents a general LDAP search request
type SearchRequest struct {
	BaseDN     string   `json:"baseDN,omitempty"`
	Filter     string   `json:"filter,omitempty"`
	Attributes []string `json:"attributes,omitempty"`
	SizeLimit  int      `json:"sizeLimit,omitempty"`
}

// SearchEntry represents a single LDAP search result entry
type SearchEntry struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

// SearchResponse represents a search response
type SearchResponse struct {
	Success bool           `json:"success"`
	Message string         `json:"message,omitempty"`
	Entries []*SearchEntry `json:"entries,omitempty"`
	Count   int            `json:"count"`
	Error   string         `json:"error,omitempty"`
}

// APIResponse represents a generic API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// UserResponse represents user data response
type UserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	User    *User  `json:"user,omitempty"`
	Error   string `json:"error,omitempty"`
}

// GroupsResponse represents groups list response
type GroupsResponse struct {
	Success bool     `json:"success"`
	Message string   `json:"message,omitempty"`
	Groups  []*Group `json:"groups,omitempty"`
	Count   int      `json:"count"`
	Error   string   `json:"error,omitempty"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status      string    `json:"status"`
	Environment string    `json:"environment"`
	Timestamp   time.Time `json:"timestamp"`
	ADServer    string    `json:"adServer,omitempty"`
	ADPort      int       `json:"adPort,omitempty"`
}

// SessionInfo represents session information
type SessionInfo struct {
	SessionID string    `json:"sessionId"`
	Username  string    `json:"username"`
	UserDN    string    `json:"userDN"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}
