# Discobot Server

The Discobot Server is a Go backend that provides REST APIs for workspace management, session orchestration, and sandbox lifecycle management.

## Overview

The server handles:
- Workspace creation and git operations
- Session lifecycle and sandbox management
- Agent configuration and credential storage
- Real-time events via Server-Sent Events
- Chat message routing to sandboxes

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Go Server                                  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    HTTP Handlers                          │  │
│  │  /api/projects/{id}/workspaces, sessions, agents, etc.   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           │                                      │
│                           ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Service Layer                          │  │
│  │  Business logic, validation, orchestration               │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           │                                      │
│         ┌─────────────────┼─────────────────┐                   │
│         ▼                 ▼                 ▼                   │
│  ┌────────────┐   ┌────────────┐   ┌────────────────────┐      │
│  │   Store    │   │  Sandbox   │   │   Git Provider     │      │
│  │   (GORM)   │   │  Provider  │   │   (local git)      │      │
│  └────────────┘   └────────────┘   └────────────────────┘      │
│         │                 │                 │                   │
│         ▼                 ▼                 ▼                   │
│    PostgreSQL/       Docker API       File System               │
│     SQLite                                                      │
└─────────────────────────────────────────────────────────────────┘
```

## Documentation

- [Architecture Overview](./docs/ARCHITECTURE.md) - System design and data flow
- [Handler Module](./docs/design/handler.md) - HTTP request handlers
- [Service Module](./docs/design/service.md) - Business logic layer
- [Store Module](./docs/design/store.md) - Data access layer
- [Sandbox Module](./docs/design/sandbox.md) - Docker integration
- [Cache System](./docs/design/cache.md) - Project-scoped cache volumes
- [Events Module](./docs/design/events.md) - SSE and event system
- [Jobs Module](./docs/design/jobs.md) - Background job processing

## Getting Started

### Prerequisites

- Go 1.23+
- Docker (for sandbox runtime)
- PostgreSQL or SQLite

### Development

```bash
# Run with auto-reload
cd server
air

# Or run directly
go run cmd/server/main.go

# Run tests
go test ./...

# Run linter
golangci-lint run
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | HTTP server port |
| `HTTPS_PORT` | disabled | Optional HTTPS server port |
| `HTTPS_TLS_MODE` | `ephemeral` | HTTPS certificate mode: `ephemeral`, `static`, or `acme` |
| `HTTPS_TLS_HOSTS` | `localhost` | Comma-separated hostnames/IPs for ephemeral cert SANs and ACME host allowlist |
| `HTTPS_TLS_CERT_FILE` | — | PEM certificate path when `HTTPS_TLS_MODE=static` |
| `HTTPS_TLS_KEY_FILE` | — | PEM private key path when `HTTPS_TLS_MODE=static` |
| `HTTPS_ACME_EMAIL` | — | Optional ACME contact email when `HTTPS_TLS_MODE=acme` |
| `CORS_ORIGINS` | computed | Comma-separated allowed origins; supports `{HTTP_PORT}` and `{HTTPS_PORT}` placeholders |
| `DATABASE_DSN` | `discobot.db` | Database connection string |
| `AUTH_ENABLED` | `false` | Enable authentication |
| `WORKSPACE_DIR` | `/tmp/workspaces` | Base directory for workspaces |
| `SANDBOX_IMAGE` | `ghcr.io/obot-platform/discobot:main` | Default sandbox image |
| `CACHE_ENABLED` | `true` | Enable project-scoped cache volumes |
| `ENCRYPTION_KEY` | (required) | Key for credential encryption |

When `HTTPS_PORT` is enabled, the server starts both HTTP and HTTPS listeners. In `ephemeral` mode it generates an in-memory self-signed certificate at startup. In `static` mode it loads the configured PEM cert/key pair. In `acme` mode it uses Go's `autocert` support and stores cached ACME state in the database encrypted with `ENCRYPTION_KEY`.

For trusted HTTPS modes (`static` and `acme`), the HTTP listener redirects normal traffic to the HTTPS listener. In `acme` mode, Go's autocert HTTP challenge paths are still served on the HTTP listener so certificate issuance and renewal continue to work.

By default, CORS origins are generated from the configured API listener ports. That includes the active HTTP API origin (`http://localhost:{PORT}` and `http://*.localhost:{PORT}`), the active HTTPS API origin when enabled (`https://localhost:{HTTPS_PORT}` and `https://*.localhost:{HTTPS_PORT}`), plus the local frontend dev origins on ports `3000` and `3100`. If you set `CORS_ORIGINS` explicitly, you can still use `{HTTP_PORT}` and `{HTTPS_PORT}` placeholders in the value.

On startup, the server first waits until each configured listener port can be bound. It probes `PORT` and `HTTPS_PORT` every 10 seconds for up to 2 minutes, immediately releases the probe listener on success, and only then continues with the normal startup sequence. This avoids restart races with a previous process that is still shutting down.

### Building

```bash
go build -o discobot-server ./cmd/server
```

## API Endpoints

### Projects

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/projects` | List projects |
| POST | `/api/projects` | Create project |
| GET | `/api/projects/{id}` | Get project |
| PUT | `/api/projects/{id}` | Update project |
| DELETE | `/api/projects/{id}` | Delete project |

### Workspaces

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/projects/{id}/workspaces` | List workspaces |
| POST | `/api/projects/{id}/workspaces` | Create workspace |
| GET | `/api/projects/{id}/workspaces/{wid}` | Get workspace |
| DELETE | `/api/projects/{id}/workspaces/{wid}` | Delete workspace |

### Sessions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/projects/{id}/sessions/{sid}` | Get session |
| PUT | `/api/projects/{id}/sessions/{sid}` | Update session |
| DELETE | `/api/projects/{id}/sessions/{sid}` | Delete session |

### Chat

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/projects/{id}/chat` | Start chat request and return JSON metadata |

### Agents

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/projects/{id}/agents` | List agents |
| POST | `/api/projects/{id}/agents` | Create agent |
| PUT | `/api/projects/{id}/agents/{aid}` | Update agent |
| DELETE | `/api/projects/{id}/agents/{aid}` | Delete agent |
| GET | `/api/projects/{id}/agents/types` | List agent types |

### User Preferences

User preferences are scoped to the authenticated user (not project-scoped).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/preferences` | List all preferences |
| PUT | `/api/preferences` | Set multiple preferences |
| GET | `/api/preferences/{key}` | Get preference by key |
| PUT | `/api/preferences/{key}` | Set/update preference |
| DELETE | `/api/preferences/{key}` | Delete preference |

**Examples:**

```bash
# Set a preference
curl -X PUT http://localhost:3001/api/preferences/theme \
  -H "Content-Type: application/json" \
  -d '{"value": "dark"}'

# Get a preference
curl http://localhost:3001/api/preferences/theme

# Set multiple preferences
curl -X PUT http://localhost:3001/api/preferences \
  -H "Content-Type: application/json" \
  -d '{"preferences": {"theme": "dark", "editor": "vim"}}'

# List all preferences
curl http://localhost:3001/api/preferences

# Delete a preference
curl -X DELETE http://localhost:3001/api/preferences/theme
```

### Events

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/projects/{id}/events` | SSE event stream |

## Project Structure

```
server/
├── cmd/server/
│   └── main.go              # Application entry point
├── internal/
│   ├── config/              # Configuration loading
│   ├── database/            # Database connection
│   ├── model/               # GORM models (User, Project, Session, UserPreference, etc.)
│   ├── store/               # Data access layer
│   ├── handler/             # HTTP handlers
│   │   ├── handler.go       # Base handler setup
│   │   ├── preferences.go   # User preferences handlers
│   │   └── ...
│   ├── service/             # Business logic
│   │   ├── preference.go    # User preferences service
│   │   └── ...
│   ├── sandbox/             # Sandbox runtime
│   │   ├── docker/          # Docker implementation
│   │   └── mock/            # Mock for testing
│   ├── git/                 # Git operations
│   ├── dispatcher/          # Job dispatcher
│   ├── jobs/                # Background jobs
│   ├── events/              # Event system
│   ├── middleware/          # HTTP middleware
│   ├── encryption/          # Credential encryption
│   └── integration/         # Integration tests
├── go.mod
└── go.sum
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `go-chi/chi` | HTTP routing |
| `gorm.io/gorm` | ORM |
| `docker/docker` | Docker SDK |
| `google/uuid` | UUID generation |
| `gorilla/websocket` | WebSocket support |

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific package
go test ./internal/service/...

# Run integration tests
go test ./internal/integration/...
```

## License

MIT
