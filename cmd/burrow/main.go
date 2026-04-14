// Burrow - A lightweight, secure secrets management API
//
// Built by Maria Mills (https://mariamills.org)
// Go, REST API design, AES-256-GCM encryption
// bcrypt token auth, SQLite, clean architecture, and security-first thinking
//
// Quick Usage:
//
//	BURROW_ENCRYPTION_KEY=<32+ char secret> \
//	BURROW_ROOT_TOKEN=<32+ char token> \
//	./burrow
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mariamills/burrow/internal/auth"
	"github.com/mariamills/burrow/internal/cluster"
	"github.com/mariamills/burrow/internal/config"
	"github.com/mariamills/burrow/internal/crypto"
	"github.com/mariamills/burrow/internal/expiry"
	"github.com/mariamills/burrow/internal/group"
	"github.com/mariamills/burrow/internal/handler"
	"github.com/mariamills/burrow/internal/identity"
	"github.com/mariamills/burrow/internal/middleware"
	"github.com/mariamills/burrow/internal/role"
	"github.com/mariamills/burrow/internal/rotation"
	"github.com/mariamills/burrow/internal/seal"
	"github.com/mariamills/burrow/internal/session"
	"github.com/mariamills/burrow/internal/store"
	burrowui "github.com/mariamills/burrow/internal/ui"
	"github.com/mariamills/burrow/internal/user"
	"github.com/mariamills/burrow/pkg/logger"
)

const version = "1.0.0"

func main() {
	// CONFIG
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error:\n%s\n\nSet required environment variables:\n"+
			"  BURROW_ENCRYPTION_KEY=<32+ char secret key>\n"+
			"  BURROW_ROOT_TOKEN=<32+ char root token>\n", err)
		os.Exit(1)
	}

	logger.SetLevel(cfg.LogLevel)
	logger.Info("starting Burrow",
		"version", version,
		"env", cfg.Environment,
		"addr", cfg.Addr(),
		"db", cfg.DBPath,
		"tls", cfg.TLSEnabled(),
		"unseal_mode", cfg.UnsealMode,
	)

	// STORE
	db, err := store.NewFromConfig(store.Config{
		Backend:     store.BackendType(cfg.StorageBackend),
		SQLitePath:  cfg.DBPath,
		PostgresURL: cfg.PostgresURL,
	})
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("database ready", "backend", cfg.StorageBackend)

	// CLUSTER
	clusterMgr, err := cluster.New(db.DB(), cluster.Config{
		Enabled:           cfg.ClusterEnabled,
		NodeID:            cfg.ClusterNodeID,
		AdvertiseAddr:     cfg.ClusterAdvertiseAddr,
		HeartbeatInterval: 10 * time.Second,
	})
	if err != nil {
		logger.Error("failed to initialize cluster", "error", err)
		os.Exit(1)
	}
	if cfg.ClusterEnabled {
		logger.Info("cluster mode enabled", "node_id", cfg.ClusterNodeID)
	}

	// PROXY TRUST
	middleware.SetTrustProxy(cfg.TrustProxy)
	if cfg.TrustProxy {
		logger.Info("proxy trust enabled - X-Forwarded-For headers will be used for IP detection")
	}

	// SEAL MANAGER
	var sealMgr *seal.Manager
	var enc *crypto.Encryptor
	var authSvc *auth.Service

	if cfg.UnsealMode == "shamir" {
		sealMgr = seal.NewManager(db.DB())
		logger.Info("shamir unseal mode - vault starts sealed until initialized/unsealed")
	} else {
		// Auto mode: use BURROW_ENCRYPTION_KEY directly
		enc, err = crypto.New([]byte(cfg.EncryptionKey))
		if err != nil {
			logger.Error("failed to initialise encryptor", "error", err)
			os.Exit(1)
		}
		logger.Info("encryption initialised", "algorithm", "AES-256-GCM")

		authSvc, err = auth.New(db, cfg.RootToken)
		if err != nil {
			logger.Error("failed to initialise auth service", "error", err)
			os.Exit(1)
		}
		logger.Info("auth service ready", "bcrypt_cost", 12)
	}

	// USER, SESSION, GROUP & ROLE SERVICES
	userSvc := user.New(db, db)
	sessionSvc := session.New(db, db)
	groupSvc := group.New(db, db)
	roleSvc := role.New(db, db, db)
	if err := roleSvc.SeedDefaults(); err != nil {
		logger.Error("failed to seed default roles", "error", err)
	}
	logger.Info("user, session, group & role services ready")

	// HANDLERS
	h := handler.New(db, authSvc, enc, version)
	h.SetUserServices(userSvc, sessionSvc)
	h.SetGroupService(groupSvc)
	h.SetRoleService(roleSvc)
	if sealMgr != nil {
		h.SetSealManager(sealMgr)
	}
	h.SetClusterManager(clusterMgr)

	// IDENTITY SERVICE
	if enc != nil {
		identitySvc := identity.New(db, db, db, db, enc)
		h.SetIdentityService(identitySvc)
		logger.Info("identity federation service ready")
	}

	// EXPIRY WORKER
	expiryCfg := expiry.DefaultConfig()
	if d, err := expiry.ParseDuration(cfg.ExpiryCheckInterval); err == nil {
		expiryCfg.CheckInterval = d
	} else {
		logger.Warn("invalid BURROW_EXPIRY_CHECK_INTERVAL, using default", "value", cfg.ExpiryCheckInterval, "error", err)
	}
	if d, err := expiry.ParseDuration(cfg.ExpiryWarnBefore); err == nil {
		expiryCfg.WarnBefore = d
	} else {
		logger.Warn("invalid BURROW_EXPIRY_WARN_BEFORE, using default", "value", cfg.ExpiryWarnBefore, "error", err)
	}
	expiryCfg.WebhookURL = cfg.ExpiryWebhookURL
	expiryWorker := expiry.New(db, db, expiryCfg)
	h.SetExpiryWorker(expiryWorker)

	// ROTATION SERVICE
	var rotationSvc *rotation.Service
	if enc != nil {
		rotationSvc = rotation.New(db, db, db, enc, db)
		h.SetRotationService(rotationSvc)
	}

	// Background workers only run on the cluster leader (or single-node)
	if clusterMgr.IsLeader() {
		go expiryWorker.Start()
		if rotationSvc != nil {
			go rotationSvc.StartWorker(expiryCfg.CheckInterval)
		}
		logger.Info("background workers started (this node is leader)")
	} else {
		logger.Info("background workers deferred (this node is follower)")
	}

	// PERMISSION RESOLVER
	middleware.SetPermissionResolver(middleware.NewPermissionResolver(db, db))

	// WEB UI
	uiHandler, err := burrowui.New(db, userSvc, sessionSvc)
	if err != nil {
		logger.Error("failed to initialize web UI", "error", err)
		os.Exit(1)
	}
	logger.Info("web UI ready at /ui/")

	// ROUTER
	mux := buildRouter(h, uiHandler, authSvc, sessionSvc, sealMgr, db, cfg)

	// SERVER
	srv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Start server in a goroutine so we can handle shutdown signals.
	serverErr := make(chan error, 1)
	go func() {
		if cfg.TLSEnabled() {
			logger.Info("listening with TLS", "addr", cfg.Addr())
			serverErr <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			if cfg.IsProduction() {
				logger.Warn("TLS is DISABLED - do not run without TLS in production")
			}
			logger.Info("listening", "addr", cfg.Addr())
			serverErr <- srv.ListenAndServe()
		}
	}()

	// GRACEFUL SHUTDOWN
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		logger.Error("server error", "error", err)
		os.Exit(1)
	case sig := <-quit:
		logger.Info("shutdown signal received", "signal", sig.String())
	}

	// Give in-flight requests 15 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}

	logger.Info("Burrow stopped cleanly")
}

// buildRouter wires all routes with their middleware chains.
func buildRouter(
	h *handler.Handler,
	uiHandler *burrowui.Handler,
	authSvc *auth.Service,
	sessionSvc *session.Service,
	sealMgr *seal.Manager,
	db *store.Store,
	cfg *config.Config,
) http.Handler {
	mux := http.NewServeMux()

	// Global middleware stack (applied to every request):
	//   Logger > SecureHeaders > CORS > RateLimit
	corsOrigin := cfg.AllowedOrigins

	globalMiddleware := chain(
		middleware.Logger,
		middleware.SecureHeaders,
		middleware.CORS(corsOrigin),
		middleware.RateLimit(cfg.RateLimitPerMin),
	)

	// SEAL GATE (applied to all protected routes)
	// In shamir mode, blocks requests when sealed. In auto mode, this is a no-op.
	var withSealGate func(http.Handler) http.Handler
	if sealMgr != nil {
		withSealGate = middleware.SealGate(sealMgr)
	} else {
		withSealGate = func(next http.Handler) http.Handler { return next }
	}

	// Auth middleware - validates Bearer token (seal-gated).
	authMw := middleware.Auth(authSvc)
	withAuth := func(next http.Handler) http.Handler { return withSealGate(authMw(next)) }

	// Session auth middleware - validates X-Session-Token header (seal-gated).
	sessionMw := middleware.SessionAuth(sessionSvc)
	withSessionAuth := func(next http.Handler) http.Handler { return withSealGate(sessionMw(next)) }

	// Audit middleware - logs to DB after handler runs.
	withAudit := middleware.Audit(db, cfg.AuditEnabled)

	// Permission middleware factories.
	requireRead := middleware.RequirePermission(modelPermRead)
	requireWrite := middleware.RequirePermission(modelPermwrite)
	requireDelete := middleware.RequirePermission(modelPermdelete)
	requireAdmin := middleware.RequirePermission(modelPermadmin)

	// Namespace access check.
	requireNS := middleware.RequireNamespace(3)

	// PUBLIC ROUTES (bypass seal gate)
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("GET /v1/sys/seal-status", h.SealStatus)
	mux.HandleFunc("POST /v1/sys/init", h.SealInit)
	mux.HandleFunc("POST /v1/sys/unseal", h.Unseal)

	// Seal endpoint - always registered. In shamir mode, seal gate + auth
	// are handled by the handler itself (requires admin token from init).
	mux.Handle("POST /v1/sys/seal",
		withSealGate(authMw(requireAdmin(http.HandlerFunc(h.Seal)))))

	// Root is served by the UI landing page (registered via uiHandler.RegisterRoutes).

	// CLUSTER ROUTES (admin)
	mux.Handle("GET /v1/sys/cluster",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.ClusterStatus)))))

	// IDENTITY PROVIDER ROUTES (admin)
	mux.Handle("POST /v1/sys/identity-providers",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.CreateIdentityProvider)))))
	mux.Handle("GET /v1/sys/identity-providers",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.ListIdentityProviders)))))
	mux.Handle("DELETE /v1/sys/identity-providers/{id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.DeleteIdentityProvider)))))

	// SSO AUTH ROUTES (public, seal-gated)
	mux.Handle("GET /v1/auth/oidc/login",
		withSealGate(http.HandlerFunc(h.OIDCLogin)))
	mux.Handle("GET /v1/auth/oidc/callback",
		withSealGate(http.HandlerFunc(h.OIDCCallback)))
	mux.Handle("POST /v1/auth/ldap/login",
		withSealGate(http.HandlerFunc(h.LDAPLogin)))

	// AUTH ROUTES (public but seal-gated)
	mux.Handle("POST /v1/auth/login",
		withSealGate(http.HandlerFunc(h.Login)))

	// AUTH ROUTES (session required)
	mux.Handle("POST /v1/auth/logout",
		withSessionAuth(http.HandlerFunc(h.Logout)))
	mux.Handle("GET /v1/auth/me",
		withSessionAuth(http.HandlerFunc(h.Me)))

	// AUTH ROUTES (admin required)
	mux.Handle("POST /v1/auth/register",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.Register)))))

	// USER ROUTES (admin required)
	mux.Handle("GET /v1/users",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.ListUsers)))))
	mux.Handle("DELETE /v1/users/{id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.DeactivateUser)))))
	mux.Handle("PUT /v1/users/{id}/password",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.ResetUserPassword)))))

	// EXPIRY ROUTES (admin required)
	mux.Handle("GET /v1/expiring",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.GetExpiringSecrets)))))

	// ROLE ROUTES (admin required)
	mux.Handle("POST /v1/roles",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.CreateRole)))))
	mux.Handle("GET /v1/roles",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.ListRoles)))))
	mux.Handle("GET /v1/roles/{id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.GetRole)))))
	mux.Handle("PUT /v1/roles/{id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.UpdateRole)))))
	mux.Handle("DELETE /v1/roles/{id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.DeleteRole)))))

	// User role assignment (admin required)
	mux.Handle("POST /v1/users/{id}/roles",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.AssignUserRole)))))
	mux.Handle("DELETE /v1/users/{id}/roles/{role_id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.RemoveUserRole)))))

	// GROUP ROUTES (admin required)
	mux.Handle("POST /v1/groups",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.CreateGroup)))))
	mux.Handle("GET /v1/groups",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.ListGroups)))))
	mux.Handle("GET /v1/groups/{id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.GetGroup)))))
	mux.Handle("PUT /v1/groups/{id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.UpdateGroup)))))
	mux.Handle("DELETE /v1/groups/{id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.DeleteGroup)))))
	mux.Handle("POST /v1/groups/{id}/members",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.AddGroupMember)))))
	mux.Handle("DELETE /v1/groups/{id}/members/{user_id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.RemoveGroupMember)))))
	mux.Handle("PUT /v1/groups/{id}/permissions",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.SetGroupPermissions)))))
	mux.Handle("POST /v1/groups/{id}/roles",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.AssignGroupRole)))))
	mux.Handle("DELETE /v1/groups/{id}/roles/{role_id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.RemoveGroupRole)))))

	// SECRET ROUTES
	mux.Handle("GET /v1/secrets/{namespace}",
		withAudit(withAuth(requireNS(requireRead(http.HandlerFunc(h.ListSecrets))))))

	mux.Handle("GET /v1/secrets/{namespace}/{key}",
		withAudit(withAuth(requireNS(requireRead(http.HandlerFunc(h.GetSecret))))))

	mux.Handle("POST /v1/secrets/{namespace}/{key}",
		withAudit(withAuth(requireNS(requireWrite(http.HandlerFunc(h.UpsertSecret))))))

	mux.Handle("DELETE /v1/secrets/{namespace}/{key}",
		withAudit(withAuth(requireNS(requireDelete(http.HandlerFunc(h.DeleteSecret))))))

	mux.Handle("DELETE /v1/secrets/{namespace}",
		withAudit(withAuth(requireNS(requireAdmin(http.HandlerFunc(h.DeleteNamespace))))))

	// ROTATION / VERSIONING ROUTES
	mux.Handle("POST /v1/secrets/{namespace}/{key}/rotate",
		withAudit(withAuth(requireNS(requireWrite(http.HandlerFunc(h.RotateSecret))))))
	mux.Handle("PUT /v1/secrets/{namespace}/{key}/rotation-policy",
		withAudit(withAuth(requireNS(requireWrite(http.HandlerFunc(h.SetRotationPolicy))))))
	mux.Handle("GET /v1/secrets/{namespace}/{key}/versions",
		withAudit(withAuth(requireNS(requireRead(http.HandlerFunc(h.ListSecretVersions))))))
	mux.Handle("GET /v1/secrets/{namespace}/{key}/versions/{version}",
		withAudit(withAuth(requireNS(requireRead(http.HandlerFunc(h.GetSecretVersion))))))

	// NAMESPACE ROUTES
	mux.Handle("GET /v1/namespaces",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.ListNamespaces)))))

	// TOKEN ROUTES
	mux.Handle("POST /v1/tokens",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.CreateToken)))))

	mux.Handle("GET /v1/tokens",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.ListTokens)))))

	mux.Handle("DELETE /v1/tokens/{id}",
		withAudit(withAuth(requireAdmin(http.HandlerFunc(h.RevokeToken)))))

	// AUDIT ROUTES
	mux.Handle("GET /v1/audit",
		withAuth(requireAdmin(http.HandlerFunc(h.GetAuditLog))))

	mux.Handle("GET /v1/audit/{namespace}",
		withAuth(middleware.RequireNamespace(3)(requireRead(http.HandlerFunc(h.GetAuditLog)))))

	// WEB UI ROUTES
	uiHandler.RegisterRoutes(mux)

	return globalMiddleware(mux)
}

// chain composes a slice of middleware into a single middleware function.
// Applied in order: chain(A, B, C)(handler) = A(B(C(handler)))
func chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// Inline permission constants to avoid import cycle
const (
	modelPermRead   = "read"
	modelPermwrite  = "write"
	modelPermdelete = "delete"
	modelPermadmin  = "admin"
)
