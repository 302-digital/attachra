package storage

import (
	"fmt"
	"sync"
)

// Factory builds a Driver from the storage configuration section.
// Concrete driver packages (s3, fs) register a Factory under their
// driver name via Register, typically from an init function or
// explicit wiring in cmd/attachra so that internal/core/storage
// itself never imports driver-specific packages (keeping this file
// free of e.g. aws-sdk-go-v2 or filesystem-specific dependencies).
//
// cfg is passed as `any` and type-asserted by the factory to its
// expected config struct; this keeps the registry decoupled from any
// single config schema.
type Factory func(cfg any) (Driver, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register associates name with factory, so that New(name, cfg) can
// later construct a Driver of that kind. Register panics if name is
// empty, factory is nil, or a factory is already registered under
// name — these are programmer errors caught at startup (typically
// from a package init), not runtime conditions.
func Register(name string, factory Factory) {
	if name == "" {
		panic("storage: Register called with empty name")
	}
	if factory == nil {
		panic("storage: Register called with nil factory for " + name)
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[name]; exists {
		panic("storage: Register called twice for driver " + name)
	}
	registry[name] = factory
}

// New constructs a Driver for the registered driver named name, using
// cfg as its driver-specific configuration. It returns an error if no
// driver is registered under name.
func New(name string, cfg any) (Driver, error) {
	registryMu.RLock()
	factory, ok := registry[name]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("storage: no driver registered for %q", name)
	}

	drv, err := factory(cfg)
	if err != nil {
		return nil, fmt.Errorf("storage: create %q driver: %w", name, err)
	}
	return drv, nil
}
