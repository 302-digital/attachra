package milter

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	dmilter "github.com/d--j/go-milter"

	"github.com/302-digital/attachra/internal/adapters/netutil"
	"github.com/302-digital/attachra/internal/core/metrics"
	"github.com/302-digital/attachra/internal/core/pipeline"
)

// Server is the Postfix milter adapter (ADR-008): it listens for
// milter connections, collects each message's envelope and body
// streamed via the milter protocol, and delegates policy decisions to
// a pipeline.Processor (ADR-002: this package depends on
// internal/core, never the reverse).
type Server struct {
	cfg       Config
	processor pipeline.Processor
	logger    *slog.Logger

	inner    *dmilter.Server
	listener net.Listener
}

// NewServer creates a milter adapter Server. processor is the Core
// pipeline used to decide the fate of each message; logger receives
// structured diagnostic and audit-relevant log entries (always
// including the queue ID where available); m receives Prometheus
// observations for the fail-open/fail-closed resolution of any
// processing error (US-7.2/T-7.2.1, ATR-192, SR-116-1) — a nil m is
// valid (metrics.Metrics methods are nil-safe).
func NewServer(cfg Config, processor pipeline.Processor, logger *slog.Logger, m *metrics.Metrics) *Server {
	cfg = cfg.normalized()

	inner := dmilter.NewServer(
		dmilter.WithDynamicMilter(func(_ uint32, _ dmilter.OptAction, _ dmilter.OptProtocol, _ dmilter.DataSize) dmilter.Milter {
			return newBackend(cfg, processor, logger, m)
		}),
		// OptChangeHeader is required to update (or delete) a header the
		// MTA already holds, which the rewrite promotion path needs to
		// change the top-level Content-Type in place and drop the
		// promoted single part's stale content headers (ATR-290).
		// OptAddHeader covers appending new headers; OptChangeBody
		// covers ReplaceBody.
		dmilter.WithAction(dmilter.OptAddHeader|dmilter.OptChangeHeader|dmilter.OptChangeBody),
		dmilter.WithMacroRequest(dmilter.StageMail, []dmilter.MacroName{dmilter.MacroMailAddr}),
		dmilter.WithMacroRequest(dmilter.StageRcpt, []dmilter.MacroName{dmilter.MacroRcptAddr}),
		dmilter.WithMacroRequest(dmilter.StageEOM, []dmilter.MacroName{dmilter.MacroQueueId}),
	)

	return &Server{
		cfg:       cfg,
		processor: processor,
		logger:    logger,
		inner:     inner,
	}
}

// ListenAndServe opens the configured listen address and serves
// milter connections until ctx is done or Shutdown is called. It
// blocks until the server stops and returns nil on a clean shutdown
// (dmilter.ErrServerClosed is treated as success).
//
// The number of concurrent sessions is bounded by
// cfg.MaxConnections and each session is bounded by
// cfg.SessionTimeout (SR-115-1).
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := listen(s.cfg.Listen)
	if err != nil {
		return err
	}
	s.listener = netutil.NewLimitListener(ln, s.cfg.MaxConnections, s.cfg.SessionTimeout)

	s.logger.Info("milter: listening", "addr", s.cfg.Listen, "failure_mode", string(s.cfg.FailureMode))

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.inner.Serve(s.listener)
	}()

	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-errCh:
		if err != nil && err != dmilter.ErrServerClosed {
			return fmt.Errorf("milter: serve: %w", err)
		}
		return nil
	}
}

// Shutdown gracefully stops the server: it stops accepting new
// connections and waits (bounded by cfg.ShutdownTimeout, or ctx if it
// carries an earlier deadline) for in-flight sessions to finish
// before forcibly closing any still open (SR-115-1).
func (s *Server) Shutdown(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, s.cfg.ShutdownTimeout)
	defer cancel()

	s.logger.Info("milter: shutting down")
	if err := s.inner.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("milter: shutdown: %w", err)
	}
	return nil
}
