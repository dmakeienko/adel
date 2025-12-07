package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"adel/config"
	"adel/middleware"
	"adel/models"
	"adel/session"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/mux"
)

// Handler holds dependencies for HTTP handlers
type Handler struct {
	config     *config.Config
	sessionMgr *session.Manager
}

// NewHandler creates a new Handler instance
func NewHandler(cfg *config.Config, sessionMgr *session.Manager) *Handler {
	return &Handler{
		config:     cfg,
		sessionMgr: sessionMgr,
	}
}

// Health handles health check requests
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	response := models.HealthResponse{
		Status:      "healthy",
		Environment: h.config.Server.Environment,
		Timestamp:   time.Now(),
		ADServer:    h.config.AD.Server,
		ADPort:      h.config.AD.Port,
	}
	writeJSON(w, http.StatusOK, response)
}

// Login handles user login and creates a session
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, models.LoginResponse{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, models.LoginResponse{
			Success: false,
			Message: "Username and password are required",
		})
		return
	}

	// Attempt login
	sess, err := h.sessionMgr.Login(req.Username, req.Password)
	if err != nil {
		slog.Warn("Login failed", "username", req.Username, "error", err)
		writeJSON(w, http.StatusUnauthorized, models.LoginResponse{
			Success: false,
			Message: "Authentication failed",
		})
		return
	}

	// Get user details after successful login
	user, err := h.getUserByDN(sess.Conn, sess.UserDN)
	if err != nil {
		slog.Error("Failed to get user details", "error", err)
	}

	writeJSON(w, http.StatusOK, models.LoginResponse{
		Success:   true,
		SessionID: sess.ID,
		Message:   "Login successful",
		User:      user,
	})
}

// Logout handles user logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req models.LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Try to get session ID from header
		req.SessionID = r.Header.Get("X-Session-ID")
	}

	if req.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Session ID is required",
		})
		return
	}

	if err := h.sessionMgr.Logout(req.SessionID); err != nil {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Logged out successfully",
	})
}

// GetUser retrieves user attributes by username
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSessionFromContext(r.Context())
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, models.UserResponse{
			Success: false,
			Error:   "Session not found",
		})
		return
	}

	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		writeJSON(w, http.StatusBadRequest, models.UserResponse{
			Success: false,
			Error:   "Username is required",
		})
		return
	}

	// Search for the user
	user, err := h.findUser(sess.Conn, username)
	if err != nil {
		writeJSON(w, http.StatusNotFound, models.UserResponse{
			Success: false,
			Error:   fmt.Sprintf("User not found: %v", err),
		})
		return
	}

	writeJSON(w, http.StatusOK, models.UserResponse{
		Success: true,
		User:    user,
	})
}

// EditUser modifies user attributes
func (h *Handler) EditUser(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSessionFromContext(r.Context())
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Error:   "Session not found",
		})
		return
	}

	var req models.EditUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request body",
		})
		return
	}

	if req.Username == "" {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Username is required",
		})
		return
	}

	if len(req.Attributes) == 0 {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "At least one attribute is required",
		})
		return
	}

	// Find user DN
	userDN, err := h.findUserDN(sess.Conn, req.Username)
	if err != nil {
		writeJSON(w, http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("User not found: %v", err),
		})
		return
	}

	// Build modify request
	modifyReq := ldap.NewModifyRequest(userDN, nil)
	for attr, value := range req.Attributes {
		if value == "" {
			modifyReq.Delete(attr, []string{})
		} else {
			modifyReq.Replace(attr, []string{value})
		}
	}

	// Execute modify
	if err := sess.Conn.Modify(modifyReq); err != nil {
		writeJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to modify user: %v", err),
		})
		return
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "User updated successfully",
	})
}

// GetAllGroups retrieves all groups from AD
func (h *Handler) GetAllGroups(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSessionFromContext(r.Context())
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, models.GroupsResponse{
			Success: false,
			Error:   "Session not found",
		})
		return
	}

	// Get optional baseDN from query params
	baseDN := r.URL.Query().Get("baseDN")
	if baseDN == "" {
		baseDN = h.config.AD.BaseDN
	}

	// Get optional filter from query params
	filter := r.URL.Query().Get("filter")
	if filter == "" {
		filter = h.config.AD.GroupFilter
	}

	// Search for groups
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"dn", "cn", "sAMAccountName", "description", "groupType", "member", "memberOf", "distinguishedName"},
		nil,
	)

	sr, err := sess.Conn.Search(searchReq)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, models.GroupsResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to search groups: %v", err),
		})
		return
	}

	groups := make([]*models.Group, 0, len(sr.Entries))
	for _, entry := range sr.Entries {
		group := &models.Group{
			DN:                entry.DN,
			CN:                entry.GetAttributeValue("cn"),
			SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
			Description:       entry.GetAttributeValue("description"),
			GroupType:         entry.GetAttributeValue("groupType"),
			Members:           entry.GetAttributeValues("member"),
			MemberOf:          entry.GetAttributeValues("memberOf"),
			DistinguishedName: entry.GetAttributeValue("distinguishedName"),
		}
		groups = append(groups, group)
	}

	writeJSON(w, http.StatusOK, models.GroupsResponse{
		Success: true,
		Groups:  groups,
		Count:   len(groups),
	})
}

// AddUserToGroup adds a user to a group
func (h *Handler) AddUserToGroup(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSessionFromContext(r.Context())
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Error:   "Session not found",
		})
		return
	}

	var req models.GroupMembershipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request body",
		})
		return
	}

	if req.Username == "" || req.GroupName == "" {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Username and groupName are required",
		})
		return
	}

	// Find user DN
	userDN, err := h.findUserDN(sess.Conn, req.Username)
	if err != nil {
		writeJSON(w, http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("User not found: %v", err),
		})
		return
	}

	// Find group DN
	groupDN, err := h.findGroupDN(sess.Conn, req.GroupName)
	if err != nil {
		writeJSON(w, http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Group not found: %v", err),
		})
		return
	}

	// Add user to group
	modifyReq := ldap.NewModifyRequest(groupDN, nil)
	modifyReq.Add("member", []string{userDN})

	slog.Info("Attempting to add user to group",
		"username", req.Username,
		"user_dn", userDN,
		"group", req.GroupName,
		"group_dn", groupDN,
	)

	if err := sess.Conn.Modify(modifyReq); err != nil {
		// Log detailed LDAP error information
		logLDAPError("AddUserToGroup", err, map[string]string{
			"username": req.Username,
			"userDN":   userDN,
			"group":    req.GroupName,
			"groupDN":  groupDN,
		})

		// Check if user is already a member
		if strings.Contains(err.Error(), "Entry Already Exists") ||
			strings.Contains(err.Error(), "LDAP Result Code 68") {
			writeJSON(w, http.StatusConflict, models.APIResponse{
				Success: false,
				Error:   "User is already a member of this group",
			})
			return
		}

		// Check for permission denied
		if strings.Contains(err.Error(), "Insufficient Access") ||
			strings.Contains(err.Error(), "LDAP Result Code 50") {
			writeJSON(w, http.StatusForbidden, models.APIResponse{
				Success: false,
				Error:   "Permission denied: You don't have rights to modify this group",
			})
			return
		}

		writeJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to add user to group: %v", err),
		})
		return
	}

	slog.Info("Successfully added user to group",
		"username", req.Username,
		"group", req.GroupName,
	)

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: fmt.Sprintf("User %s added to group %s successfully", req.Username, req.GroupName),
	})
}

// RemoveUserFromGroup removes a user from a group
func (h *Handler) RemoveUserFromGroup(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSessionFromContext(r.Context())
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Error:   "Session not found",
		})
		return
	}

	var req models.GroupMembershipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Invalid request body",
		})
		return
	}

	if req.Username == "" || req.GroupName == "" {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Username and groupName are required",
		})
		return
	}

	// Find user DN
	userDN, err := h.findUserDN(sess.Conn, req.Username)
	if err != nil {
		writeJSON(w, http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("User not found: %v", err),
		})
		return
	}

	// Find group DN
	groupDN, err := h.findGroupDN(sess.Conn, req.GroupName)
	if err != nil {
		writeJSON(w, http.StatusNotFound, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Group not found: %v", err),
		})
		return
	}

	// Remove user from group
	modifyReq := ldap.NewModifyRequest(groupDN, nil)
	modifyReq.Delete("member", []string{userDN})

	slog.Info("Attempting to remove user from group",
		"username", req.Username,
		"user_dn", userDN,
		"group", req.GroupName,
		"group_dn", groupDN,
	)

	if err := sess.Conn.Modify(modifyReq); err != nil {
		// Log detailed LDAP error information
		logLDAPError("RemoveUserFromGroup", err, map[string]string{
			"username": req.Username,
			"userDN":   userDN,
			"group":    req.GroupName,
			"groupDN":  groupDN,
		})

		// Check if user is not a member
		if strings.Contains(err.Error(), "No Such Attribute") ||
			strings.Contains(err.Error(), "LDAP Result Code 16") {
			writeJSON(w, http.StatusNotFound, models.APIResponse{
				Success: false,
				Error:   "User is not a member of this group",
			})
			return
		}

		// Check for permission denied
		if strings.Contains(err.Error(), "Insufficient Access") ||
			strings.Contains(err.Error(), "LDAP Result Code 50") {
			writeJSON(w, http.StatusForbidden, models.APIResponse{
				Success: false,
				Error:   "Permission denied: You don't have rights to modify this group",
			})
			return
		}

		writeJSON(w, http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to remove user from group: %v", err),
		})
		return
	}

	slog.Info("Successfully removed user from group",
		"username", req.Username,
		"group", req.GroupName,
	)

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: fmt.Sprintf("User %s removed from group %s successfully", req.Username, req.GroupName),
	})
}

// GetCurrentUser returns information about the currently logged in user
func (h *Handler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSessionFromContext(r.Context())
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, models.UserResponse{
			Success: false,
			Error:   "Session not found",
		})
		return
	}

	user, err := h.getUserByDN(sess.Conn, sess.UserDN)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, models.UserResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get user: %v", err),
		})
		return
	}

	writeJSON(w, http.StatusOK, models.UserResponse{
		Success: true,
		User:    user,
	})
}

// Search performs a general LDAP search with custom baseDN and filter
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSessionFromContext(r.Context())
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, models.SearchResponse{
			Success: false,
			Error:   "Session not found",
		})
		return
	}

	// Get parameters from query string (GET) or request body (POST)
	var baseDN, filter string
	var attributes []string
	var sizeLimit int

	if r.Method == http.MethodGet {
		baseDN = r.URL.Query().Get("baseDN")
		filter = r.URL.Query().Get("filter")
		if attrs := r.URL.Query().Get("attributes"); attrs != "" {
			attributes = strings.Split(attrs, ",")
		}
		if limitStr := r.URL.Query().Get("sizeLimit"); limitStr != "" {
			_, _ = fmt.Sscanf(limitStr, "%d", &sizeLimit)
		}
	} else {
		var req models.SearchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, models.SearchResponse{
				Success: false,
				Error:   "Invalid request body",
			})
			return
		}
		baseDN = req.BaseDN
		filter = req.Filter
		attributes = req.Attributes
		sizeLimit = req.SizeLimit
	}

	// Use defaults if not provided
	if baseDN == "" {
		baseDN = h.config.AD.BaseDN
	}
	if filter == "" {
		filter = h.config.AD.SearchFilter
	}
	if len(attributes) == 0 {
		attributes = []string{"*"}
	}

	// Perform LDAP search
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit, 0, false,
		filter,
		attributes,
		nil,
	)

	sr, err := sess.Conn.Search(searchReq)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, models.SearchResponse{
			Success: false,
			Error:   fmt.Sprintf("Search failed: %v", err),
		})
		return
	}

	// Convert entries to response format
	entries := make([]*models.SearchEntry, 0, len(sr.Entries))
	for _, entry := range sr.Entries {
		attrs := make(map[string][]string)
		for _, attr := range entry.Attributes {
			attrs[attr.Name] = attr.Values
		}
		entries = append(entries, &models.SearchEntry{
			DN:         entry.DN,
			Attributes: attrs,
		})
	}

	writeJSON(w, http.StatusOK, models.SearchResponse{
		Success: true,
		Entries: entries,
		Count:   len(entries),
	})
}

// SessionInfo returns information about the current session
func (h *Handler) SessionInfo(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   "Session ID is required",
		})
		return
	}

	info, err := h.sessionMgr.GetSessionInfo(sessionID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    info,
	})
}

// Helper functions

// findUser searches for a user and returns their details
func (h *Handler) findUser(conn *ldap.Conn, username string) (*models.User, error) {
	searchReq := ldap.NewSearchRequest(
		h.config.AD.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(&%s(|(sAMAccountName=%s)(userPrincipalName=%s)(cn=%s)))",
			h.config.AD.UserFilter,
			ldap.EscapeFilter(username),
			ldap.EscapeFilter(username),
			ldap.EscapeFilter(username)),
		getUserAttributes(),
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return entryToUser(sr.Entries[0]), nil
}

// findUserDN finds the DN for a user
func (h *Handler) findUserDN(conn *ldap.Conn, username string) (string, error) {
	searchReq := ldap.NewSearchRequest(
		h.config.AD.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(&%s(|(sAMAccountName=%s)(userPrincipalName=%s)(cn=%s)))",
			h.config.AD.UserFilter,
			ldap.EscapeFilter(username),
			ldap.EscapeFilter(username),
			ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("user not found")
	}

	return sr.Entries[0].DN, nil
}

// findGroupDN finds the DN for a group
func (h *Handler) findGroupDN(conn *ldap.Conn, groupName string) (string, error) {
	searchReq := ldap.NewSearchRequest(
		h.config.AD.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(&%s(|(sAMAccountName=%s)(cn=%s)))",
			h.config.AD.GroupFilter,
			ldap.EscapeFilter(groupName),
			ldap.EscapeFilter(groupName)),
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("group not found")
	}

	return sr.Entries[0].DN, nil
}

// getUserByDN retrieves a user by their DN
func (h *Handler) getUserByDN(conn *ldap.Conn, dn string) (*models.User, error) {
	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		getUserAttributes(),
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return entryToUser(sr.Entries[0]), nil
}

// getUserAttributes returns the list of user attributes to fetch
func getUserAttributes() []string {
	return []string{
		"dn",
		"sAMAccountName",
		"userPrincipalName",
		"displayName",
		"givenName",
		"sn",
		"mail",
		"department",
		"title",
		"manager",
		"memberOf",
		"description",
		"telephoneNumber",
		"mobile",
		"employeeID",
		"company",
		"streetAddress",
		"l",
		"st",
		"postalCode",
		"c",
		"whenCreated",
		"whenChanged",
		"userAccountControl",
		"pwdLastSet",
		"accountExpires",
		"msDS-UserPasswordExpiryTimeComputed",
	}
}

// entryToUser converts an LDAP entry to a User model
func entryToUser(entry *ldap.Entry) *models.User {
	user := &models.User{
		DN:                 entry.DN,
		SAMAccountName:     entry.GetAttributeValue("sAMAccountName"),
		UserPrincipalName:  entry.GetAttributeValue("userPrincipalName"),
		DisplayName:        entry.GetAttributeValue("displayName"),
		GivenName:          entry.GetAttributeValue("givenName"),
		Surname:            entry.GetAttributeValue("sn"),
		Email:              entry.GetAttributeValue("mail"),
		Department:         entry.GetAttributeValue("department"),
		Title:              entry.GetAttributeValue("title"),
		Manager:            entry.GetAttributeValue("manager"),
		MemberOf:           entry.GetAttributeValues("memberOf"),
		Description:        entry.GetAttributeValue("description"),
		TelephoneNumber:    entry.GetAttributeValue("telephoneNumber"),
		Mobile:             entry.GetAttributeValue("mobile"),
		EmployeeID:         entry.GetAttributeValue("employeeID"),
		Company:            entry.GetAttributeValue("company"),
		StreetAddress:      entry.GetAttributeValue("streetAddress"),
		City:               entry.GetAttributeValue("l"),
		State:              entry.GetAttributeValue("st"),
		PostalCode:         entry.GetAttributeValue("postalCode"),
		Country:            entry.GetAttributeValue("c"),
		WhenCreated:        entry.GetAttributeValue("whenCreated"),
		WhenChanged:        entry.GetAttributeValue("whenChanged"),
		PwdLastSet:         filetimeToUnixTime(entry.GetAttributeValue("pwdLastSet")),
		Enabled:            isUserEnabled(entry.GetAttributeValue("userAccountControl")),
		AccountExpires:     filetimeToUnixTime(entry.GetAttributeValue("accountExpires")),
		PasswordExpiryDate: filetimeToUnixTime(entry.GetAttributeValue("msDS-UserPasswordExpiryTimeComputed")),
	}

	return user
}

// isUserEnabled checks if user account is enabled based on userAccountControl
func isUserEnabled(uac string) bool {
	if uac == "" {
		return true // Default to enabled if not set
	}
	// UAC flag 0x0002 (2) means account is disabled
	var uacInt int
	if n, err := fmt.Sscanf(uac, "%d", &uacInt); err != nil || n != 1 {
		return true
	}
	return (uacInt & 0x0002) == 0
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Error encoding JSON response", "error", err)
	}
}

// logLDAPError logs detailed LDAP error information for debugging
func logLDAPError(operation string, err error, context map[string]string) {
	attrs := []interface{}{
		"operation", operation,
		"error", err.Error(),
		"error_type", fmt.Sprintf("%T", err),
	}

	// Try to extract LDAP-specific error details
	if ldapErr, ok := err.(*ldap.Error); ok {
		attrs = append(attrs,
			"ldap_result_code", ldapErr.ResultCode,
			"ldap_result_description", ldap.LDAPResultCodeMap[ldapErr.ResultCode],
			"ldap_matched_dn", ldapErr.MatchedDN,
		)
		if ldapErr.Packet != nil {
			attrs = append(attrs, "ldap_packet", fmt.Sprintf("%v", ldapErr.Packet))
		}
	}

	// Add context information
	for key, value := range context {
		attrs = append(attrs, key, value)
	}

	slog.Error("LDAP operation failed", attrs...)
}

// filetimeToUnixTime converts a Windows FILETIME string to Unix time
// Returns nil for special AD values: 0 (not set/must change at next logon) and 0x7FFFFFFFFFFFFFFF (never expires)
func filetimeToUnixTime(filetimeStr string) *time.Time {
	// 0: The user must change their password at the next logon or value is not set
	if filetimeStr == "" || filetimeStr == "0" {
		return nil
	}

	val, err := strconv.ParseUint(filetimeStr, 10, 64)
	if err != nil {
		slog.Error("Cannot parse filetime", "value", filetimeStr, "error", err)
		return nil
	}

	// 0x7FFFFFFFFFFFFFFF (9223372036854775807) = never expires in Active Directory
	// Also check for values that would overflow or are unreasonably far in the future
	if val >= 9223372036854775807 {
		return nil
	}

	// Windows FILETIME epoch starts at January 1, 1601
	// Unix epoch starts at January 1, 1970
	// The difference is 116444736000000000 in 100-nanosecond intervals
	const windowsToUnixEpochDiff = 116444736000000000

	if val < windowsToUnixEpochDiff {
		// Invalid value - before Unix epoch
		return nil
	}

	// Subtract the Unix epoch difference
	val -= windowsToUnixEpochDiff

	// Convert from 100-nanosecond intervals to nanoseconds
	nanoseconds := int64(val * 100)

	// Convert to UTC Go time.Time
	t := time.Unix(0, nanoseconds).UTC()
	return &t
}
