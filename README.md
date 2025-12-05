# Adel - Active Directory Web Server

Active Directory Easy Liaison - A Go-based HTTPS server that provides REST API access to Active Directory using LDAP/LDAPS.

## Features

- **Session-Based Authentication**: Users login with their own AD credentials (no service account required)
- **HTTPS Server**: Secure TLS/SSL connections by default
- **Active Directory Integration**: Connect to AD/LDAP servers with configurable settings
- **User Management**: Get and edit user attributes
- **Group Management**: List groups, add/remove users from groups
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

The server will start on `https://localhost:8443`

## API Endpoints

### Public Endpoints

#### Health Check
```bash
curl -k https://localhost:8443/health
```

#### Login
```bash
curl -k -X POST https://localhost:8443/api/v1/login \
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
curl -k -X POST https://localhost:8443/api/v1/logout \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"your-session-id"}'
```

### Protected Endpoints (require X-Session-ID header)

#### Get Current User
```bash
curl -k https://localhost:8443/api/v1/users/me \
  -H "X-Session-ID: your-session-id"
```

#### Get User by Username
```bash
curl -k https://localhost:8443/api/v1/users/johndoe \
  -H "X-Session-ID: your-session-id"
```

#### Edit User Attributes
```bash
curl -k -X PUT https://localhost:8443/api/v1/users \
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

#### Get All Groups
```bash
curl -k https://localhost:8443/api/v1/groups \
  -H "X-Session-ID: your-session-id"

# With optional baseDN
curl -k "https://localhost:8443/api/v1/groups?baseDN=ou=Groups,dc=example,dc=com" \
  -H "X-Session-ID: your-session-id"
```

#### Add User to Group
```bash
curl -k -X POST https://localhost:8443/api/v1/groups/add-member \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{"username":"johndoe","groupName":"Developers"}'
```

#### Remove User from Group
```bash
curl -k -X POST https://localhost:8443/api/v1/groups/remove-member \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{"username":"johndoe","groupName":"Developers"}'
```

#### Search (with custom Base DN)
```bash
# GET request with query parameters
curl -k "https://localhost:8443/api/v1/search?baseDN=ou=Users,dc=example,dc=com&filter=(objectClass=user)&attributes=cn,mail,title&sizeLimit=100" \
  -H "X-Session-ID: your-session-id"

# POST request with JSON body
curl -k -X POST https://localhost:8443/api/v1/search \
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
| PORT | Server port | 8443 |
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
| TLS_ENABLED | Enable HTTPS | true |
| TLS_CERT_FILE | Path to TLS certificate | certs/server.crt |
| TLS_KEY_FILE | Path to TLS private key | certs/server.key |

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

## Security Notes

1. **TLS Certificates**: In production, use certificates from a trusted CA
2. **Session Tokens**: Session IDs are cryptographically random 64-character hex strings
3. **No Service Account**: Users authenticate with their own AD credentials
4. **Automatic Cleanup**: Expired sessions are automatically removed
5. **Security Headers**: HSTS, X-Frame-Options, X-XSS-Protection are enabled

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
