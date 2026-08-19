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
	PwdLastSet         *time.Time        `json:"pwdLastSet"`
	AccountExpires     *time.Time        `json:"accountExpires"`
	Enabled            bool              `json:"enabled"`
	Attributes         map[string]string `json:"attributes,omitempty"`
	PasswordExpiryDate *time.Time        `json:"passwordExpiryDate"`
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

	// Nested reports that the user is not a direct member of this group: membership
	// comes from a group they are in being a member of it. Set by ResolveGroups when
	// expansion is requested; always false for directly requested DNs.
	Nested bool `json:"nested,omitempty"`
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"` //nolint:gosec // G117: this is a request DTO, not a hardcoded secret
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

// SearchRequest represents a general LDAP search request.
// Provide either Query (safe plain-text search across common attributes)
// or Filter (raw LDAP filter string, for advanced use). Query takes precedence.
type SearchRequest struct {
	BaseDN     string   `json:"baseDN,omitempty"`
	Query      string   `json:"query,omitempty"`
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

// ResolveGroupsRequest asks for details of a specific set of groups by DN, so callers
// can enrich known memberships without listing the directory.
type ResolveGroupsRequest struct {
	DNs []string `json:"dns"`
	// Nested requests transitive expansion: each resolved group's own memberOf is
	// followed, so the response also contains groups the user belongs to indirectly.
	// Off by default to keep the plain lookup cheap.
	Nested bool `json:"nested,omitempty"`
}

// GroupMember is a single member of a group. Groups can contain users, contacts and
// other groups, so IsGroup tells the UI whether the entry can be linked to a user page.
type GroupMember struct {
	DN             string `json:"dn"`
	CN             string `json:"cn"`
	SAMAccountName string `json:"sAMAccountName,omitempty"`
	DisplayName    string `json:"displayName,omitempty"`
	Email          string `json:"mail,omitempty"`
	IsGroup        bool   `json:"isGroup,omitempty"`
}

// GroupDetailResponse represents a single group together with its members.
type GroupDetailResponse struct {
	Success bool           `json:"success"`
	Message string         `json:"message,omitempty"`
	Group   *Group         `json:"group,omitempty"`
	Members []*GroupMember `json:"members,omitempty"`
	// MemberCount is the number of members returned. It can be lower than the group's
	// true size when the directory caps the result at MaxSearchResults; Truncated says so.
	MemberCount int    `json:"memberCount"`
	Truncated   bool   `json:"truncated,omitempty"`
	Error       string `json:"error,omitempty"`
}

// GroupMembershipResponse reports a user's group memberships together with the
// leadership roles derived from them.
type GroupMembershipResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	// GroupDetails holds the LDAP details of every group the user belongs to, including
	// groups that carry no lead or PM role.
	GroupDetails []*Group `json:"group_details"`
	// LeadGroupMembership holds the unique wildcard identifiers (e.g. "CN=engineering-*")
	// of the groups in which the user is a lead or PM. Empty for a user with no role.
	LeadGroupMembership []string `json:"lead_group_membership"`
	Error               string   `json:"error,omitempty"`
}

// TeamGroup is one group a lead is responsible for, together with its members.
type TeamGroup struct {
	Group   *Group         `json:"group"`
	Members []*GroupMember `json:"members"`
	// Truncated reports that the directory capped this group's member list.
	Truncated bool `json:"truncated,omitempty"`
}

// TeamResponse lists the groups the caller leads and everyone in them. It backs the
// UI's Team view, which shows a lead their subordinates without exposing the directory.
type TeamResponse struct {
	Success bool         `json:"success"`
	Message string       `json:"message,omitempty"`
	Groups  []*TeamGroup `json:"groups"`
	// MemberCount is the number of distinct users across all groups, so a person in
	// two of the lead's teams is counted once.
	MemberCount int `json:"memberCount"`
	// LeadGroupMembership echoes the wildcard identifiers defining this scope.
	LeadGroupMembership []string `json:"lead_group_membership"`
	Error               string   `json:"error,omitempty"`
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
	Version     string    `json:"version"`
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
	// CanSearch reports whether this session may use the search endpoint. It lets the
	// UI hide search controls; the server-side check remains the enforcement point.
	CanSearch bool `json:"canSearch"`
	// CanResetPassword reports whether this session may use the privileged password
	// reset endpoint. It controls UI visibility only; the endpoint checks again.
	CanResetPassword bool `json:"canResetPassword"`
	// LeadGroupMembership holds the wildcard identifiers of the groups in which this
	// user is a lead or PM, so the UI can scope its search view to them. Empty when the
	// user holds no such role.
	LeadGroupMembership []string `json:"lead_group_membership,omitempty"`
}

// ChangeUserPasswordRequest represents a password change request
type ChangeUserPasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// ResetUserPasswordRequest represents a privileged password reset request.
// The target username is carried in the URL and never accepted from this body.
type ResetUserPasswordRequest struct {
	NewPassword string `json:"newPassword"`
}
