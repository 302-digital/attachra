// Command attachra is the single static binary entrypoint for the
// Attachra attachment policy engine. It wires up configuration,
// logging, the milter adapter, the public download adapter
// (internal/adapters/http, US-6.2) and a shared graceful shutdown for
// both.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	adapterhttp "github.com/302-digital/attachra/internal/adapters/http"
	"github.com/302-digital/attachra/internal/adapters/milter"
	"github.com/302-digital/attachra/internal/config"
	"github.com/302-digital/attachra/internal/core/link"
	"github.com/302-digital/attachra/internal/core/message"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/pipeline"
	"github.com/302-digital/attachra/internal/core/policy"
	"github.com/302-digital/attachra/internal/core/retention"
	"github.com/302-digital/attachra/internal/core/rewrite"
	"github.com/302-digital/attachra/internal/core/storage"
	fsstorage "github.com/302-digital/attachra/internal/core/storage/fs"
	s3storage "github.com/302-digital/attachra/internal/core/storage/s3"
	"github.com/302-digital/attachra/internal/core/store/sqlite"
	"github.com/302-digital/attachra/internal/logging"
	"github.com/302-digital/attachra/internal/version"
)

// pinger is the optional readiness-check capability a storage.Driver
// implementation may support (US-7.2/T-7.2.3, ATR-194): both
// fsstorage.Driver and s3storage.Driver implement it, but it is not
// part of the storage.Driver interface itself (a driver without a
// natural lightweight probe is still a valid Driver). run type-asserts
// for it when building the /readyz storage check below.
type pinger interface {
	Ping(ctx context.Context) error
}

// storageConfig builds the driver-specific config value expected by
// the storage.Driver registered under cfg.Storage.Driver (see
// internal/core/storage/fs and internal/core/storage/s3's init()
// registrations: importing either package for its exported types, as
// this file does above, is enough to run its init() and register the
// driver — no blank import is needed).
func storageConfig(cfg config.Config) any {
	switch cfg.Storage.Driver {
	case fsstorage.DriverName:
		return fsstorage.Config{BaseDir: cfg.Storage.FS.BaseDir}
	case s3storage.DriverName:
		return s3storage.Config{
			Endpoint:    cfg.Storage.S3.Endpoint,
			Region:      cfg.Storage.S3.Region,
			Bucket:      cfg.Storage.S3.Bucket,
			AccessKey:   cfg.Storage.S3.AccessKey.Value(),
			SecretKey:   cfg.Storage.S3.SecretKey.Value(),
			PathStyle:   cfg.Storage.S3.PathStyle,
			SSE:         cfg.Storage.S3.SSE,
			SSEKMSKeyID: cfg.Storage.S3.SSEKMSKeyID,
		}
	default:
		// config.Config.Validate already rejects any other driver
		// name before run reaches here; this branch exists only so
		// storageConfig has a total, non-panicking fallback.
		return nil
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run contains the actual entrypoint logic and returns a process exit
// code, keeping main() itself trivial and testable indirectly.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attachra", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("config", "", "path to YAML configuration file")
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// `attachra version` subcommand, in addition to the --version flag.
	if fs.NArg() > 0 && fs.Arg(0) == "version" {
		*showVersion = true
	}

	if *showVersion {
		if _, err := fmt.Fprintln(stdout, version.String()); err != nil {
			return 1
		}
		return 0
	}

	// `attachra policy validate <file>` subcommand (T-4.2.3). Handled
	// before config.Load: policy validation is a standalone, config-
	// independent operation (an operator checking a policy file before
	// wiring it up at all), matching the `version` subcommand's
	// precedent of short-circuiting the normal server startup path.
	if fs.NArg() > 0 && fs.Arg(0) == "policy" {
		return runPolicyCommand(fs.Args()[1:], stdout, stderr)
	}

	// `attachra setup ...` (ATR-320): a first-run wizard that generates
	// attachra.yaml/policy.yaml. Same short-circuit precedent as
	// `policy validate` above — setup's whole purpose is to CREATE a
	// config, so it must run before config.Load, not after it.
	if fs.NArg() > 0 && fs.Arg(0) == "setup" {
		return runSetupCommand(fs.Args()[1:], os.Stdin, stdout, stderr)
	}

	// `attachra doctor ...` (ATR-321): a standalone, read-only
	// diagnostic pass over an installation (config/policy validity,
	// storage/database directory ownership, listener reachability,
	// public URL/SPF/postfix wiring). It has its own --config flag
	// (defaulting to the packaged install's /etc/attachra/attachra.yaml
	// rather than this flag set's empty default) and does not touch any
	// of the state cmd/attachra otherwise wires up below, so it is
	// short-circuited here before config.Load, same as `policy` above.
	if fs.NArg() > 0 && fs.Arg(0) == "doctor" {
		return runDoctorCommand(fs.Args()[1:], stdout, stderr)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "attachra: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return 1
	}

	// `attachra audit export ...` (T-7.1.3, ATR-191). Handled before the
	// stdout-writing application logger is constructed and before its
	// startup banner is logged: export's stdout output is meant to be
	// machine-readable JSON Lines (SR-128-3), so nothing else may share
	// that stream. Only the metadata store is opened for this
	// subcommand's own sake; the storage driver/policy/server wiring
	// below is skipped entirely, matching the `policy validate`
	// subcommand's precedent of short-circuiting the normal server
	// startup path.
	if fs.NArg() > 0 && fs.Arg(0) == "audit" {
		metadataStore, err := sqlite.Open(cfg.Database.Path)
		if err != nil {
			fmt.Fprintf(stderr, "attachra: metadata store init failed: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
			return 1
		}
		defer func() { _ = metadataStore.Close() }()

		return runAuditCommand(fs.Args()[1:], metadataStore, stdout, stderr)
	}

	// `attachra link hold|unhold|revoke ...` (ATR-258): an interim
	// admin/operator CLI surface for the ATR-257 hold mechanism and the
	// US-6.3 revoke operations, ahead of the full REST API (ATR-197) and
	// attachractl CLI (ATR-204). Same short-circuit precedent as `audit`
	// above: only the metadata store and link engine are wired up, the
	// milter/HTTP server startup below is skipped entirely.
	if fs.NArg() > 0 && fs.Arg(0) == "link" {
		metadataStore, err := sqlite.Open(cfg.Database.Path)
		if err != nil {
			fmt.Fprintf(stderr, "attachra: metadata store init failed: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
			return 1
		}
		defer func() { _ = metadataStore.Close() }()

		linkEngine, err := link.NewEngine(metadataStore, link.Defaults{
			TTL:          time.Duration(cfg.Links.DefaultTTLSeconds) * time.Second,
			MaxDownloads: cfg.Links.DefaultMaxDownloads,
			TokenBytes:   cfg.Links.TokenBytes,
			Retention:    time.Duration(cfg.Links.DefaultRetentionSeconds) * time.Second,
		}, metadataStore, nil) // nil logger: this short-circuited subcommand only holds/unholds/revokes, never calls CreateLinks, so there is no retention clamp to log (ATR-294).
		if err != nil {
			fmt.Fprintf(stderr, "attachra: link engine init failed: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
			return 1
		}

		return runLinkCommand(fs.Args()[1:], metadataStore, linkEngine, stdout, stderr)
	}

	// `attachra token create ...` (ATR-201): the bootstrap path by which an
	// operator mints the FIRST API token, since the REST API itself is
	// deny-by-default and unreachable without one (a chicken-and-egg the
	// API cannot solve for itself). Same short-circuit precedent as `audit`
	// and `link` above: only the metadata store is opened, and the raw
	// secret is printed to stdout exactly once, so nothing else may share
	// that stream (the secret is never persisted — invariant #5).
	if fs.NArg() > 0 && fs.Arg(0) == "token" {
		metadataStore, err := sqlite.Open(cfg.Database.Path)
		if err != nil {
			fmt.Fprintf(stderr, "attachra: metadata store init failed: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
			return 1
		}
		defer func() { _ = metadataStore.Close() }()

		return runTokenCommand(fs.Args()[1:], metadataStore, metadataStore, stdout, stderr)
	}

	logger, err := logging.New(stdout, cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		fmt.Fprintf(stderr, "attachra: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
		return 1
	}

	logger.Info("attachra starting",
		"version", version.Version,
		"commit", version.Commit,
		"date", version.Date,
	)

	metadataStore, err := sqlite.Open(cfg.Database.Path)
	if err != nil {
		logger.Error("metadata store init failed", "error", err.Error())
		return 1
	}
	defer func() {
		if closeErr := metadataStore.Close(); closeErr != nil {
			logger.Error("metadata store close failed", "error", closeErr.Error())
		}
	}()

	drv, err := storage.New(cfg.Storage.Driver, storageConfig(cfg))
	if err != nil {
		logger.Error("storage driver init failed", "error", err.Error())
		return 1
	}

	linkEngine, err := link.NewEngine(metadataStore, link.Defaults{
		TTL:          time.Duration(cfg.Links.DefaultTTLSeconds) * time.Second,
		MaxDownloads: cfg.Links.DefaultMaxDownloads,
		TokenBytes:   cfg.Links.TokenBytes,
		Retention:    time.Duration(cfg.Links.DefaultRetentionSeconds) * time.Second,
	}, metadataStore, logger)
	if err != nil {
		logger.Error("link engine init failed", "error", err.Error())
		return 1
	}

	// Policy loading (US-4.2/T-4.2.1). An empty policy.path preserves
	// pre-US-4.x behavior: no policy is loaded and the milter pipeline
	// keeps using pipeline.PassthroughProcessor below, exactly as
	// before this feature existed.
	var policyStore *policy.Store
	if cfg.Policy.Path != "" {
		policyStore, err = policy.NewStore(cfg.Policy.Path)
		if err != nil {
			fmt.Fprintf(stderr, "attachra: %v\n", err) //nolint:errcheck // best-effort diagnostic on stderr
			return 1
		}
		p := policyStore.Current()
		logger.Info("policy loaded",
			"path", cfg.Policy.Path,
			"name", p.Name,
			"rules", len(p.Rules),
			"dry_run", cfg.Policy.DryRun,
		)
	}

	// appMetrics holds every Prometheus collector this process exposes
	// (US-7.2/T-7.2.1, ATR-192), shared across the pipeline, the milter
	// adapter's fail-open/fail-closed resolution, and the download
	// adapter's /metrics endpoint.
	appMetrics := metrics.New()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP triggers a policy reload (T-4.2.1). This runs regardless
	// of whether a policy is configured, so an operator sending SIGHUP
	// to a passthrough-mode instance gets a clear log line instead of
	// the signal being silently swallowed by the Go runtime's default
	// SIGHUP handling.
	stopPolicyReload := watchPolicyReload(ctx, policyStore, logger)
	defer stopPolicyReload()

	// Background storage-retention cleanup (US-5.3/ATR-179): a nil
	// sweeper (retention.disabled by config) makes watchRetentionCleanup
	// a no-op, matching watchPolicyReload's own "nothing configured,
	// nothing to run" handling.
	var retentionSweeper *retention.Sweeper
	if cfg.Retention.Enabled {
		retentionSweeper, err = retention.New(retention.Params{
			Metadata:  metadataStore,
			Storage:   drv,
			AuditSink: metadataStore,
			// Audit-log retention (ATR-308, ADR-017): opt-in, off by
			// default (audit_retention_seconds == 0 leaves AuditRetention
			// zero, which disables truncation regardless of the
			// Truncator). Wired only alongside the storage sweep, so it
			// also requires retention.enabled.
			AuditTruncator: metadataStore,
			AuditRetention: time.Duration(cfg.Retention.AuditRetentionSeconds) * time.Second,
			Metrics:        appMetrics,
			Logger:         logger,
			ChunkSize:      cfg.Retention.ChunkSize,
		})
		if err != nil {
			logger.Error("retention sweeper init failed", "error", err.Error())
			return 1
		}
	}
	stopRetentionCleanup := watchRetentionCleanup(ctx, retentionSweeper, time.Duration(cfg.Retention.IntervalSeconds)*time.Second, logger)
	defer stopRetentionCleanup()

	// The end-to-end attachment pipeline (ATR-167) only engages when a
	// policy is configured; an empty policy.path keeps the
	// pre-US-4.x/community-edition PassthroughProcessor behavior
	// (config.PolicyConfig.Path's own doc comment).
	var processor pipeline.Processor = pipeline.PassthroughProcessor{}
	if policyStore != nil {
		tmpl, err := rewrite.LoadTemplates(rewrite.TemplateConfig{})
		if err != nil {
			logger.Error("rewrite template load failed", "error", err.Error())
			return 1
		}

		attachmentProcessor, err := pipeline.NewAttachmentProcessor(pipeline.AttachmentProcessorParams{
			PolicyStore: policyStore,
			Storage:     drv,
			LinkEngine:  linkEngine,
			Templates:   tmpl,
			Limits: message.Limits{
				MaxParts:     cfg.Limits.MaxMIMEParts,
				MaxDepth:     cfg.Limits.MaxMIMEDepth,
				MaxHeaders:   0, // message.Limits.normalized falls back to DefaultLimits; no dedicated config field exists yet.
				MaxPartSize:  cfg.Limits.MaxAttachmentSize,
				MaxTotalSize: cfg.Limits.MaxMessageSize,
			},
			MaxAttachmentSize: cfg.Limits.MaxAttachmentSize,
			InlineMaxSize:     cfg.Limits.InlineMaxSize,
			PublicBaseURL:     cfg.PublicBaseURL,
			DryRun:            cfg.Policy.DryRun,
			Logger:            logger,
			AuditSink:         metadataStore,
			Metrics:           appMetrics,
			SpoolDir:          cfg.Spool.Dir,
		})
		if err != nil {
			logger.Error("attachment processor init failed", "error", err.Error())
			return 1
		}
		processor = attachmentProcessor
	}

	milterServer := milter.NewServer(milter.Config{
		Listen:          cfg.Milter.Listen,
		FailureMode:     milter.FailureMode(cfg.Milter.FailureMode),
		MaxConnections:  cfg.Limits.MilterMaxConnections,
		SessionTimeout:  time.Duration(cfg.Limits.MilterTimeout) * time.Second,
		MaxMessageSize:  cfg.Limits.MaxMessageSize,
		ShutdownTimeout: 30 * time.Second,
		SpoolDir:        cfg.Spool.Dir,
	}, processor, logger, appMetrics)

	// readinessChecks backs GET /readyz (US-7.2/T-7.2.3, ATR-194):
	// metadata store reachability, storage driver reachability (only
	// for drivers that implement the optional pinger capability above),
	// and the policy engine having a currently active Policy whenever
	// one is configured. None of these checks can currently fail once
	// the process has started successfully (a failed policy/link/store
	// initialization above already exits before this point, and
	// policy.Store.Reload never leaves Current() nil on a failed
	// reload — see its own doc comment), but the checks are still
	// wired up per the acceptance criteria and as a defensive probe
	// against a future change to those invariants.
	readinessChecks := []adapterhttp.ReadinessCheck{
		{Name: "database", Check: metadataStore.Ping},
	}
	if p, ok := drv.(pinger); ok {
		readinessChecks = append(readinessChecks, adapterhttp.ReadinessCheck{Name: "storage", Check: p.Ping})
	}
	if policyStore != nil {
		readinessChecks = append(readinessChecks, adapterhttp.ReadinessCheck{
			Name: "policy",
			Check: func(_ context.Context) error {
				if policyStore.Current() == nil {
					return fmt.Errorf("no active policy loaded")
				}
				return nil
			},
		})
	}

	// trustedProxies is the parsed form of cfg.HTTP.TrustedProxies
	// (ATR-311), shared by both the download adapter and the REST API
	// below so a request's client identity — used for audit, rate
	// limiting and the API's auth-failure throttle alike — is resolved
	// consistently regardless of which surface handled it. cfg.Validate
	// (called from config.Load above) already rejected any unparsable
	// CIDR, so an error here indicates a bug in that validation rather
	// than a normal operator mistake; fail closed rather than silently
	// trusting nothing or panicking.
	trustedProxies, err := adapterhttp.ParseTrustedProxies(cfg.HTTP.TrustedProxies)
	if err != nil {
		logger.Error("http.trusted_proxies: invalid CIDR", "error", err.Error())
		return 1
	}

	// The admin/automation REST API (US-8.1/E8, ATR-196) shares the same
	// HTTP server, timeouts, connection ceiling and graceful shutdown as
	// the download surface, but lives under /api/v1 behind Bearer-token
	// auth (SR-130-1). It reuses metadataStore as both its token store
	// and its store.MetadataStore (ADR-011: API-token hashes live in the
	// same metadata DB as link tokens) and as its audit sink, so
	// API-token lifecycle changes land in the same append-only log as
	// every other event (ATR-296); it also shares the same linkEngine
	// the milter pipeline uses, so link mutations made through the API
	// (ATR-197/T-8.1.3) are audited identically to CLI-driven ones
	// (ATR-258).
	apiHandler := adapterhttp.NewAPIHandler(metadataStore, metadataStore, linkEngine, policyStore, logger, metadataStore, metadataStore, appMetrics, adapterhttp.APIConfig{
		TrustedProxies: trustedProxies,
	})

	// adminListen translates config.AdminConfig's explicit,
	// two-field opt-out (ATR-292 security review) into
	// adapterhttp.Config's simpler "empty means fold" contract: the
	// ONLY way to produce an empty adminListen here is
	// cfg.Admin.FoldIntoHTTP being true — config.Load already
	// guarantees cfg.Admin.Listen itself is never silently empty
	// (an empty value from any source, absent explicit
	// fold_into_http, is normalized back to the safe default before
	// Load returns). NewServer logs loudly whenever it receives an
	// empty AdminListen, so this fold is never silent at runtime
	// either.
	adminListen := cfg.Admin.Listen
	if cfg.Admin.FoldIntoHTTP {
		adminListen = ""
	}

	httpTimeout := time.Duration(cfg.Limits.HTTPTimeout) * time.Second
	downloadServer := adapterhttp.NewServer(adapterhttp.Config{
		Listen:          cfg.HTTP.Listen,
		AdminListen:     adminListen,
		ReadTimeout:     httpTimeout,
		WriteTimeout:    httpTimeout,
		IdleTimeout:     httpTimeout,
		MaxConnections:  cfg.Limits.MilterMaxConnections, // Shares the same operator-tunable connection ceiling as milter (SR-115-2) until a dedicated limit is introduced.
		ShutdownTimeout: 30 * time.Second,
		RateLimit: adapterhttp.RateLimitConfig{
			PerIPRequestsPerMinute:  cfg.HTTP.RateLimit.PerIPPerMinute,
			PerIPBurst:              cfg.HTTP.RateLimit.PerIPBurst,
			GlobalRequestsPerMinute: cfg.HTTP.RateLimit.GlobalPerMinute,
			GlobalBurst:             cfg.HTTP.RateLimit.GlobalBurst,
			NotFoundPerIPPerMinute:  cfg.HTTP.RateLimit.NotFoundPerIPPerMinute,
			TarpitDelay:             time.Duration(cfg.HTTP.RateLimit.TarpitDelaySeconds * float64(time.Second)),
		},
		TrustedProxies: trustedProxies,
	}, linkEngine, metadataStore, drv, logger, metadataStore, appMetrics, readinessChecks, apiHandler)

	// Both adapters are started as independent goroutines sharing ctx:
	// each owns its own ListenAndServe call (which itself performs a
	// bounded graceful Shutdown once ctx is done), and run's own
	// goroutine waits for both to finish before returning, so neither
	// server outlives this function (no dangling goroutines).
	errCh := make(chan error, 2)
	go func() { errCh <- namedErr("milter", milterServer.ListenAndServe(ctx)) }()
	go func() { errCh <- namedErr("http", downloadServer.ListenAndServe(ctx)) }()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			logger.Error("adapter server stopped with error", "error", err.Error())
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	if firstErr != nil {
		return 1
	}

	logger.Info("attachra shutting down")
	return 0
}

// namedErr wraps err (if non-nil) with a component name prefix so the
// combined error log line in run identifies which adapter failed.
func namedErr(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", name, err)
}
