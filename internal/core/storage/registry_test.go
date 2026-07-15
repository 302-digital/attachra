package storage

import (
	"context"
	"io"
	"testing"
)

// noopDriver is a minimal Driver used only to verify registry wiring.
type noopDriver struct{}

func (noopDriver) Put(context.Context, string, io.Reader, int64) error { return nil }
func (noopDriver) Get(context.Context, string) (io.ReadCloser, error)  { return nil, nil }
func (noopDriver) Delete(context.Context, string) error                { return nil }
func (noopDriver) Stat(context.Context, string) (ObjectInfo, error)    { return ObjectInfo{}, nil }

func TestRegister_AndNew(t *testing.T) {
	name := "test-noop-register-and-new"
	Register(name, func(_ any) (Driver, error) {
		return noopDriver{}, nil
	})

	drv, err := New(name, nil)
	if err != nil {
		t.Fatalf("New(%q) error = %v, want nil", name, err)
	}
	if _, ok := drv.(noopDriver); !ok {
		t.Errorf("New(%q) returned %T, want noopDriver", name, drv)
	}
}

func TestNew_UnknownDriver(t *testing.T) {
	_, err := New("test-unknown-driver-xyz", nil)
	if err == nil {
		t.Fatal("New() error = nil, want error for unregistered driver name")
	}
}

func TestRegister_PanicsOnEmptyName(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Register(\"\", ...) did not panic")
		}
	}()
	Register("", func(_ any) (Driver, error) { return noopDriver{}, nil })
}

func TestRegister_PanicsOnNilFactory(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Register(name, nil) did not panic")
		}
	}()
	Register("test-nil-factory", nil)
}

func TestRegister_PanicsOnDuplicate(t *testing.T) {
	name := "test-duplicate-register"
	Register(name, func(_ any) (Driver, error) { return noopDriver{}, nil })

	defer func() {
		if recover() == nil {
			t.Error("Register() called twice did not panic")
		}
	}()
	Register(name, func(_ any) (Driver, error) { return noopDriver{}, nil })
}
