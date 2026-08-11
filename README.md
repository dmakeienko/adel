# Adel - Active Directory Engagement Layer

[![SonarQube Cloud](https://sonarcloud.io/images/project_badges/sonarcloud-light.svg)](https://sonarcloud.io/summary/new_code?id=dmakeienko_adel)

Active Directory Engagement Layer - A Go-based HTTPS server that provides REST API access to Active Directory using LDAP/LDAPS.

## Features

- **Session-Based Authentication**: Users login with their own AD credentials (no service account required)
- **HTTPS Server**: Secure TLS/SSL connections by default
- **Active Directory Integration**: Connect to AD/LDAP servers with configurable settings
- **User Management**: Get and edit user attributes
- **Group Management**: List groups, add/remove users from groups
- **Group Inspection**: Look up a single group and list its members, with nested groups linked rather than flattened
- **Nested Group Resolution**: Optionally expand a user's indirect memberships, inherited through groups that are themselves members of other groups
- **LDAP/LDAPS Support**: Connect via LDAP (389) or LDAPS (636) with optional CA certificates
- **Session Management**: Automatic session cleanup and secure session handling
- **Middleware**: CORS, logging, recovery, and security headers

## Project Structure

```
adel/
├── main.go                 # Application entry point
├── config/
│   └── config.go           # Configuration management
├── handlers/
│   └── handler.go          # HTTP handlers for AD operations
├── middleware/
│   └── middleware.go       # HTTP middleware (CORS, logging, auth)
├── models/
│   └── models.go           # Models and DTOs
├── session/
│   └── manager.go          # Session and LDAP connection management
├── certs/                  # TLS certificates (generated)
├── .env.example            # Environment variables template
├── Dockerfile              # Docker configuration
├── Makefile                # Build and development commands
└── go.mod                  # Go module definition
```

## Getting Started

### Prerequisites

- Go 1.23 or higher
- Access to an Active Directory server
- OpenSSL (for generating certificates)

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd adel
   ```

2. Copy the environment file:
   ```bash
   cp .env.example .env
   ```

3. Update the `.env` file with your Active Directory settings:
   ```bash
   AD_SERVER=your-ad-server.example.com
   AD_PORT=389
   AD_BASE_DN=dc=example,dc=com
   ```

4. Generate TLS certificates for HTTPS:
   ```bash
   make certs
   ```

5. Install dependencies:
   ```bash
   go mod tidy
   ```

### Running the Application

```bash
# Build and run
make run

# Or run directly
make run-dev

# Or with Docker
make docker-build
make docker-run
```

The server will start on `https://localhost:8080`

## API Endpoints

### Public Endpoints

#### Health Check
```bash
curl -k https://localhost:8080/health
```

#### Login
```bash
curl -k -X POST https://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"johndoe","password":"password123"}'
```

Response:
```json
{
  "success": true,
  "sessionId": "abc123...",
  "message": "Login successful",
  "user": { ... }
}
```

#### Logout
```bash
curl -k -X POST https://localhost:8080/api/v1/logout \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"your-session-id"}'
```

### Protected Endpoints (require X-Session-ID header)

#### Get Current User
```bash
curl -k https://localhost:8080/api/v1/users/me \
  -H "X-Session-ID: your-session-id"
```

#### Get User by Username
```bash
curl -k https://localhost:8080/api/v1/users/johndoe \
  -H "X-Session-ID: your-session-id"
```

#### Edit User Attributes
```bash
curl -k -X PUT https://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{
    "username": "johndoe",
    "attributes": {
      "title": "Senior Engineer",
      "department": "Engineering"
    }
  }'
```

#### Search Groups

A `query` (minimum 2 characters) or an explicit `filter` is **required**. Listing every
group is not supported: it walks the entire directory and is prohibitively expensive on
real domains. `query` matches `cn` and `sAMAccountName` as a substring, so partial input
returns partial matches. Results are capped by `AD_MAX_SEARCH_RESULTS`.

```bash
curl -k "https://localhost:8080/api/v1/groups?query=admins" \
  -H "X-Session-ID: your-session-id"

# With optional baseDN
curl -k "https://localhost:8080/api/v1/groups?query=admins&baseDN=ou=Groups,dc=example,dc=com" \
  -H "X-Session-ID: your-session-id"
```

Omitting both `query` and `filter` returns `400`.

#### Resolve Groups by DN

Looks up a known set of groups in a single search. Used by the UI to show a user's own
memberships without listing the directory. Unlike `/groups`, this is not gated by
`AD_SEARCH_ALLOWED_GROUPS`, since the request is bounded by the DNs supplied.

```bash
curl -k -X POST https://localhost:8080/api/v1/groups/resolve \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{"dns":["CN=Developers,OU=Groups,DC=example,DC=com"]}'
```

##### Nested Groups

A user's `memberOf` lists only *direct* memberships. Pass `"nested": true` to also walk
each resolved group's own `memberOf`, returning the groups the user belongs to
indirectly:

```bash
curl -k -X POST https://localhost:8080/api/v1/groups/resolve \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{"dns":["CN=Developers,OU=Groups,DC=example,DC=com"],"nested":true}'
```

Inherited groups are flagged with `"nested": true`; directly requested ones omit the
field:

```json
{
  "success": true,
  "count": 2,
  "groups": [
    {
      "dn": "CN=Developers,OU=Groups,DC=example,DC=com",
      "cn": "Developers",
      "sAMAccountName": "Developers"
    },
    {
      "dn": "CN=All Staff,OU=Groups,DC=example,DC=com",
      "cn": "All Staff",
      "sAMAccountName": "All Staff",
      "nested": true
    }
  ]
}
```

The transitive set is computed by the directory in a single extra search, using the same
`LDAP_MATCHING_RULE_IN_CHAIN` extension as the login-time allow-list check (see
[Search Scope and Exclusions](#search-scope-and-exclusions)). There is no client-side
hierarchy walk, so nesting depth and membership cycles are the server's problem, not
ours. Results are capped by `AD_MAX_SEARCH_RESULTS`.

The expansion resolves memberships for the **session's own user**, so `nested: true` is
only meaningful when the supplied DNs are that user's groups. Directories that do not
implement the matching rule return nothing extra, and the response degrades to the
directly requested groups rather than failing.

In the web UI, the group membership table requests nested groups and labels them with a
`nested` badge. A **Direct only / All** toggle controls whether they are listed,
defaulting to direct only. Inherited memberships render with a disabled checkbox: they
live on the parent group, so removing the user from the nested group would have no
effect — the parent membership has to be changed instead.

#### Add User to Group
```bash
curl -k -X POST https://localhost:8080/api/v1/groups/add-member \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{"username":"johndoe","groupName":"Developers"}'
```

#### Remove User from Group
```bash
curl -k -X POST https://localhost:8080/api/v1/groups/remove-member \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{"username":"johndoe","groupName":"Developers"}'
```

#### Inspect a Group

Returns a single group by `cn` or `sAMAccountName`, together with its members. Gated by
`AD_SEARCH_ALLOWED_GROUPS`, like `/groups`: it exposes directory contents beyond the
caller's own memberships, so it is directory browsing rather than a lookup bounded by who
the caller is.

```bash
curl -k "https://localhost:8080/api/v1/groups/Developers" \
  -H "X-Session-ID: your-session-id"

# Group names containing spaces or slashes must be URL-encoded
curl -k "https://localhost:8080/api/v1/groups/Domain%20Admins" \
  -H "X-Session-ID: your-session-id"
```

```json
{
  "success": true,
  "group": {
    "dn": "CN=Developers,OU=Groups,DC=example,DC=com",
    "cn": "Developers",
    "sAMAccountName": "Developers",
    "description": "Engineering team"
  },
  "members": [
    {
      "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
      "cn": "John Doe",
      "sAMAccountName": "johndoe",
      "displayName": "John Doe",
      "mail": "john.doe@example.com"
    },
    {
      "dn": "CN=Platform,OU=Groups,DC=example,DC=com",
      "cn": "Platform",
      "isGroup": true
    }
  ],
  "memberCount": 2
}
```

Members are found by searching for entries whose `memberOf` points at the group, rather
than by reading the group's own `member` attribute. That keeps it to a single search, lets
the directory apply the size cap, and returns each member's attributes in the same round
trip.

Only **direct** members are listed. A member that is itself a group comes back as one
entry flagged `"isGroup": true` rather than being flattened into its own members; in the
UI that entry links through to that group's page.

Results are capped by `AD_MAX_SEARCH_RESULTS`. When the directory truncates the list the
response sets `"truncated": true`, and `memberCount` reflects what was returned rather
than the group's true size. Groups and containers hidden by `AD_EXCLUDED_GROUPS` /
`AD_EXCLUDED_OBJECTS` are filtered from the member list, and an excluded group reports
`404` rather than `403`, so its existence is not disclosed.

In the web UI this backs a **Groups** tab in the sidebar, where a group can be searched
for and its members listed. Group names in the user's membership table are links to the
same page. Both are hidden for sessions without search permission, so users are not
offered a route that can only fail.

#### Search (with custom Base DN)
```bash
# GET request with query parameters
curl -k "https://localhost:8080/api/v1/search?baseDN=ou=Users,dc=example,dc=com&filter=(objectClass=user)&attributes=cn,mail,title&sizeLimit=100" \
  -H "X-Session-ID: your-session-id"

# POST request with JSON body
curl -k -X POST https://localhost:8080/api/v1/search \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{
    "baseDN": "ou=Users,dc=example,dc=com",
    "filter": "(objectClass=user)",
    "attributes": ["cn", "mail", "title"],
    "sizeLimit": 100
  }'
```

Response:
```json
{
  "success": true,
  "entries": [
    {
      "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
      "attributes": {
        "cn": ["John Doe"],
        "mail": ["john.doe@example.com"],
        "title": ["Engineer"]
      }
    }
  ],
  "count": 1
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | Server port | 8080 |
| ENVIRONMENT | Environment (development/production) | development |
| READ_TIMEOUT | Read timeout in seconds | 60 |
| WRITE_TIMEOUT | Write timeout in seconds | 60 |
| IDLE_TIMEOUT | Idle timeout in seconds | 60 |
| AD_SERVER | Active Directory server hostname | (required) |
| AD_PORT | LDAP port | 389 |
| AD_BASE_DN | Base DN for searches | (required) |
| AD_USE_SSL | Use LDAPS instead of LDAP | false |
| AD_SKIP_TLS | Skip TLS verification | false |
| AD_CA_CERT_PATH | Path to CA certificate for LDAPS | |
| AD_USER_FILTER | LDAP filter for users | (objectClass=user) |
| AD_GROUP_FILTER | LDAP filter for groups | (objectClass=group) |
| AD_SEARCH_FILTER | LDAP filter for general searches | (objectClass=*) |
| AD_SEARCH_BASE_DN | Restrict searches to a specific OU (falls back to AD_BASE_DN if empty) | |
| AD_MAX_SEARCH_RESULTS | Maximum entries returned by any single LDAP search (LDAP size limit) | 200 |
| AD_EXCLUDED_OBJECTS | Semicolon-separated list of DN path fragments (OUs, CN containers) to exclude from results | |
| AD_EXCLUDED_GROUPS | Semicolon-separated list of group CNs or DNs to exclude from results | |
| AD_SEARCH_ALLOWED_GROUPS | Semicolon-separated group CNs or DNs allowed to use `/api/v1/search`; empty allows all authenticated users | |
| TLS_ENABLED | Enable HTTPS | true |
| TLS_CERT_FILE | Path to TLS certificate | certs/server.crt |
| TLS_KEY_FILE | Path to TLS private key | certs/server.key |

### Search Scope and Exclusions

To restrict API searches to a specific OU instead of the entire domain:

```bash
AD_BASE_DN=DC=example,DC=com                       # Used for authentication (broad)
AD_SEARCH_BASE_DN=OU=Corporate,DC=example,DC=com   # Used for listing/searching (narrow)
```

To hide specific containers from all search results (users, groups, and generic search):

```bash
AD_EXCLUDED_OBJECTS=CN=Builtin,DC=example,DC=com;OU=Disabled Users,DC=example,DC=com
```

To hide specific groups from group listings and lookups:

```bash
AD_EXCLUDED_GROUPS=Domain Admins;Schema Admins;Enterprise Admins
```

To allow only members of selected AD groups to use the directory-browsing endpoints:

```bash
AD_SEARCH_ALLOWED_GROUPS=Helpdesk;CN=Directory Admins,OU=Groups,DC=example,DC=com
```

This gates `/api/v1/search`, `/api/v1/groups` (group search) and
`/api/v1/groups/{groupName}` (group inspection) — the endpoints that expose directory
contents beyond the caller's own record. `/api/v1/groups/resolve` is deliberately not
gated: it is bounded by the DNs the caller supplies.

Group CN and DN matching is case-insensitive. Use a full DN when groups with the same CN exist in multiple OUs.

Nested group membership is resolved: a user in a group that is itself a member of an
allowed group is permitted. This uses the Active Directory `LDAP_MATCHING_RULE_IN_CHAIN`
extension (OID `1.2.840.113556.1.4.1941`); directories that do not implement it fall back
to direct `memberOf` values, which is logged at warning level.

Memberships are resolved once at login and cached for the lifetime of the session, so
group changes in AD take effect on the user's next login rather than immediately.

Users outside the allow-list receive `403` from those endpoints, and the web UI hides the
search fields, the sidebar **Groups** tab and the group links in the membership table for
them, based on the `canSearch` field of `GET /api/v1/session`. The server-side check is the
enforcement point; hiding the controls is a convenience only.

### LDAPS Configuration

To use LDAPS (LDAP over SSL):

```bash
AD_USE_SSL=true
AD_PORT=636
AD_CA_CERT_PATH=/path/to/ca-cert.pem  # Optional: for certificate verification
```

## Development

### Available Make Commands

```bash
make help        # Show all available commands
make build       # Build the application
make run         # Build and run
make run-dev     # Run without building
make certs       # Generate self-signed certificates
make test        # Run tests
make fmt         # Format code
make vet         # Vet code
make lint        # Run linter
make tidy        # Tidy dependencies
make dev         # Run with hot reload (requires air)
```

### Hot Reload Development

```bash
make install-dev  # Install air
make dev          # Run with hot reload
```

## Docker

```bash
# Build image
make docker-build

# Run container
make docker-run
```

## Kubernetes (Helm)

A Helm chart is provided in [`charts/adel`](charts/adel) to deploy the container to Kubernetes. It is also published as a Helm repo on every release.

### Install from the Helm repo

```bash
helm repo add adel https://dmakeienko.github.io/adel/
helm repo update

# Install (AD_SERVER and AD_BASE_DN are required)
helm install adel adel/adel \
  --set config.ad.server=dc1.example.com \
  --set config.ad.baseDN="dc=example,dc=com"

# Or with a values file
helm install adel adel/adel -f my-values.yaml --namespace adel --create-namespace

# Upgrade to the latest chart version
helm repo update
helm upgrade adel adel/adel --namespace adel
```

### Install from source

```bash
# Lint and render
make helm-lint
make helm-template

# Install (AD_SERVER and AD_BASE_DN are required)
helm install adel charts/adel \
  --set config.ad.server=dc1.example.com \
  --set config.ad.baseDN="dc=example,dc=com"

# Or with a values file
helm install adel charts/adel -f my-values.yaml --namespace adel --create-namespace
```

Key values (see [`charts/adel/values.yaml`](charts/adel/values.yaml) for the full list):

| Value | Description | Default |
|-------|-------------|---------|
| `image.repository` | Container image | `dmakeienko/adel` |
| `image.tag` | Image tag | `.Chart.AppVersion` |
| `config.ad.server` / `config.ad.baseDN` | Required AD connection settings | `""` |
| `tls.enabled` / `tls.secretName` | Terminate TLS in the Go server using a `kubernetes.io/tls` Secret | `false` |
| `config.ad.caCertSecretName` | Secret containing a CA cert for LDAPS, mounted at `/certs/ca` | `""` |
| `ingress.enabled` | Expose via Ingress | `false` |
| `autoscaling.enabled` | Enable HPA | `false` |

In most setups, leave `tls.enabled=false` and terminate TLS at the Ingress instead.

## Security Notes

1. **TLS Certificates**: In production, use certificates from a trusted CA
2. **Session Tokens**: Session IDs are cryptographically random 64-character hex strings
3. **No Service Account**: Users authenticate with their own AD credentials
4. **Automatic Cleanup**: Expired sessions are automatically removed
5. **Security Headers**: HSTS, X-Frame-Options, X-XSS-Protection are enabled

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
