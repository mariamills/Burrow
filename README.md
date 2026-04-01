# Burrow

A lightweight, secure secrets management REST API built in Go.

Store API keys, database passwords, and environment variables encrypted at rest — retrieve them at runtime instead of hardcoding in `.env` files.

Go, security engineering, and clean API design.

## License

This project is licensed under the [Elastic License 2.0 (ELv2)](./LICENSE).

**You are free to** use, modify, and redistribute this software.

**You may not** provide it to third parties as a hosted or managed service, or sell it as a commercial product. Only the original author ([Maria Mills](https://mariamills.org)) retains commercial rights.

---

## Security Model

| Layer | Implementation |
|-------|---------------|
| **Encryption at rest** | AES-256-GCM with per-secret random nonces via HKDF-SHA256 key derivation |
| **Authentication** | Bearer tokens (bcrypt cost 12) + user sessions (SHA-256 hashed) |
| **Authorization** | RBAC with predefined roles, group-scoped namespace permissions |
| **Seal/Unseal** | Shamir's secret sharing — K-of-N threshold to unlock the vault |
| **Transport** | TLS enforced in production; HTTP/2 ready |
| **Audit trail** | Append-only log of every access attempt with IP, user-agent, status |
| **Rate limiting** | Per-IP sliding window (configurable) |
| **Security headers** | HSTS, X-Content-Type-Options, no-store Cache-Control, CSP |
| **Secret rotation** | Automatic rotation policies, full version history, callback URLs |
| **Identity federation** | OIDC/LDAP providers, auto-provisioned users |

---

## Quick Start

```bash
# 1. Generate secrets (copy output into your .env)
openssl rand -base64 48   # → BURROW_ENCRYPTION_KEY
openssl rand -base64 32   # → BURROW_ROOT_TOKEN

# 2. Configure
cp .env.example .env
# Edit .env with your generated values

# 3. Run with Docker Compose
docker compose up -d

# 4. Verify
curl http://localhost:8080/health
```

Or run directly with Go:

```bash
export BURROW_ENCRYPTION_KEY="$(openssl rand -base64 48)"
export BURROW_ROOT_TOKEN="$(openssl rand -base64 32)"
go run ./cmd/burrow
```

> **Note:** By default Burrow binds to `127.0.0.1` (localhost only). Set `BURROW_HOST=0.0.0.0` to listen on all interfaces.

---

## API Reference

All authenticated endpoints require:
```
Authorization: Bearer <token>
```

### Health (no auth)
```
GET /health
```

### Secrets

```bash
# Write a secret (creates or updates)
POST /v1/secrets/{namespace}/{key}
Content-Type: application/json
{"value": "super-secret-value", "description": "My database password"}

# Read a secret (returns decrypted value)
GET /v1/secrets/{namespace}/{key}

# List secrets in a namespace (NO values, metadata only)
GET /v1/secrets/{namespace}

# Search secrets by key pattern
GET /v1/secrets/{namespace}?q=DB_

# Delete a secret
DELETE /v1/secrets/{namespace}/{key}

# Delete an entire namespace (admin only)
DELETE /v1/secrets/{namespace}
```

### Tokens (admin only)

```bash
# Create a scoped token
POST /v1/tokens
{
  "name": "my-nextjs-app",
  "namespaces": ["production"],
  "permissions": ["read"],
  "expires_at": "2026-12-31T00:00:00Z"  # optional
}
# Returns raw token ONCE. Store it immediately.

# List all tokens
GET /v1/tokens

# Revoke a token
DELETE /v1/tokens/{id}
```

### Audit Log (admin only)

```bash
# Get all audit events
GET /v1/audit?limit=100

# Get audit events for a namespace
GET /v1/audit/{namespace}
```

---

## Usage Example: Next.js Integration

Instead of:
```js
// Bad: credentials in .env exposed on disk
const db = new Client({ password: process.env.DB_PASSWORD });
```

Do:
```js
// Better: fetch at runtime from Burrow
async function getSecret(key) {
  const res = await fetch(`${process.env.BURROW_URL}/v1/secrets/production/${key}`, {
    headers: { Authorization: `Bearer ${process.env.BURROW_TOKEN}` }
  });
  const { data } = await res.json();
  return data.value;
}

const dbPassword = await getSecret('DB_PASSWORD');
const db = new Client({ password: dbPassword });
```

Your `.env` only needs `BURROW_URL` and `BURROW_TOKEN` - **everything else lives in the vault**.

---

## Namespace Design

Organize secrets by environment and service:

```
production/DB_PASSWORD
production/STRIPE_SECRET_KEY
production/SENDGRID_API_KEY

staging/DB_PASSWORD
staging/STRIPE_SECRET_KEY

myapp/REDIS_URL
myapp/JWT_SECRET
```

Create tokens scoped to specific namespaces:
- Your production Next.js app → token with `namespaces: ["production"]`, `permissions: ["read"]`
- Your CI/CD pipeline → token with `namespaces: ["staging"]`, `permissions: ["read", "write"]`
- You (admin) → root token with access to everything

---

## Deployment on Hetzner / Coolify

1. Add this repo to Coolify as a Docker Compose application
2. Set environment variables in Coolify's secrets panel:
   - `BURROW_ENCRYPTION_KEY` (generate with `openssl rand -base64 48`)
   - `BURROW_ROOT_TOKEN` (generate with `openssl rand -base64 32`)
   - `BURROW_ENV=production`
   - `BURROW_TLS_CERT` / `BURROW_TLS_KEY` (or use Coolify's built-in Traefik TLS)
3. Set `BURROW_DB_PATH` to a persistent volume path
4. Deploy

> **Important**: The SQLite database is your vault. Back it up. Consider mounting it on a Hetzner Volume (block storage) rather than the container filesystem.

---

## Project Structure

```
burrow/
├── cmd/burrow/
│   └── main.go                # Entry point, router wiring, graceful shutdown
├── internal/
│   ├── auth/                  # Token creation, bcrypt validation, in-memory cache
│   ├── cluster/               # Multi-node coordination, leader election
│   ├── config/                # Environment variable loading & validation
│   ├── crypto/                # AES-256-GCM encryption, HKDF key derivation
│   ├── domain/                # Core interfaces for dependency injection
│   ├── expiry/                # Secret TTL management, expiry webhooks
│   ├── group/                 # Group management, membership, permissions
│   ├── handler/               # 60+ HTTP route handlers
│   ├── identity/              # Identity federation (OIDC/LDAP)
│   ├── middleware/            # Auth, audit, rate limit, CORS, seal gate
│   ├── migrate/               # Numbered migration runner (9 versions)
│   ├── model/                 # Domain types, DTOs
│   ├── role/                  # RBAC, predefined role seeding
│   ├── rotation/              # Secret rotation, versioning, policies
│   ├── seal/                  # Shamir's secret sharing (K-of-N unsealing)
│   ├── session/               # User session tokens, TTL cleanup
│   ├── store/                 # SQLite data layer (interface-backed)
│   ├── ui/                    # Server-rendered web UI
│   └── user/                  # User account management
├── pkg/
│   └── logger/                # Structured JSON logging (slog)
├── deployments/
│   └── Dockerfile             # Multi-stage build → distroless runtime
├── docker-compose.yml
├── .env.example
└── go.mod
```

---

## Architecture Decisions

**Why Go?** Single binary deployment, excellent standard library HTTP support, strong typing, and performance that comfortably handles secrets retrieval at any scale.

**Why SQLite?** Zero infrastructure dependencies, WAL mode for concurrent reads, and perfectly adequate for the use case. The store layer is behind interfaces (`domain.SecretStore`, `domain.TokenStore`, etc.) - swap it for a Postgres implementation without touching any other layer.

**Why HKDF for key derivation?** The encryption key in the env var is treated as key material, not a final key. HKDF-SHA256 derives a well-distributed 256-bit key regardless of the input's quality, and the domain label `"burrow-secret-encryption-v1"` allows future key versioning.

**Why bcrypt cost 12?** ~250ms per hash on modern hardware. Fast enough for human operators creating tokens. Slow enough that brute-forcing a stolen hash database is economically impractical at scale.

**Why interfaces?** The handler and middleware layers depend on interfaces (`domain.Encryptor`, `domain.Authenticator`, `domain.SecretStore`) rather than concrete types. This enables unit testing with mocks, and will allow swapping storage backends (e.g., SQLite, Postgres) without touching application logic.

---

## Implemented Features

- **User accounts & sessions** — email/password login, session management, activation/deactivation
- **Groups & teams** — group-scoped namespace permissions, membership management
- **Role-based access control** — predefined roles (Admin, Viewer, Editor, Operator), user & group role assignment
- **Secret TTLs & rotation** — expiry warnings, automatic rotation with callback URLs, full version history
- **Shamir's secret sharing** — split master key across N operators, require K-of-N threshold to unseal
- **SSO/LDAP/OIDC** — federated identity providers, auto-provisioned users
- **HA clustering** — leader election, multi-node coordination, heartbeat monitoring
- **Web UI** — server-rendered Go templates

## Roadmap

- **Postgres storage backend** — interface-ready, driver integration pending
- **External group mapping** — map OIDC/LDAP groups to Burrow groups
- **Secret sharing & one-time links** — securely share secrets with expiring URLs
- **CLI client** — command-line tool for developers and CI/CD pipelines

---

*Built with Go · AES-256-GCM · bcrypt · SQLite WAL · distroless containers*
