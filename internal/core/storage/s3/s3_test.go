package s3

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/302-digital/attachra/internal/core/storage"
)

func TestNew_RequiresBucket(t *testing.T) {
	_, err := New(context.Background(), Config{Region: "us-east-1"})
	if err == nil {
		t.Fatal("New() error = nil, want error for missing bucket")
	}
}

func TestNew_RequiresRegion(t *testing.T) {
	_, err := New(context.Background(), Config{Bucket: "attachra"})
	if err == nil {
		t.Fatal("New() error = nil, want error for missing region")
	}
}

func TestNew_ValidMinimalConfig(t *testing.T) {
	// No network call is made by New itself (AWS SDK config loading
	// is local); this exercises the success path without touching the
	// network.
	drv, err := New(context.Background(), Config{
		Bucket:    "attachra",
		Region:    "us-east-1",
		Endpoint:  "http://localhost:9000",
		PathStyle: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	if drv == nil {
		t.Fatal("New() returned nil driver")
	}
}

func TestParseSSE(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		want    types.ServerSideEncryption
		wantErr bool
	}{
		{"none", "", "", false},
		{"aes256", "AES256", types.ServerSideEncryptionAes256, false},
		{"kms", "aws:kms", types.ServerSideEncryptionAwsKms, false},
		{"invalid", "rot13", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSSE(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSSE(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseSSE(%q) = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

func TestNew_InvalidSSE(t *testing.T) {
	_, err := New(context.Background(), Config{
		Bucket: "attachra",
		Region: "us-east-1",
		SSE:    "not-a-real-mode",
	})
	if err == nil {
		t.Fatal("New() error = nil, want error for invalid sse mode")
	}
}

func TestPut_Get_Delete_Stat_RejectInvalidKeys(t *testing.T) {
	drv, err := New(context.Background(), Config{Bucket: "attachra", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	badKey := "../etc/passwd"

	if err := drv.Put(context.Background(), badKey, nil, 0); !errors.Is(err, storage.ErrInvalidKey) {
		t.Errorf("Put() error = %v, want wrapping storage.ErrInvalidKey", err)
	}
	if _, err := drv.Get(context.Background(), badKey); !errors.Is(err, storage.ErrInvalidKey) {
		t.Errorf("Get() error = %v, want wrapping storage.ErrInvalidKey", err)
	}
	if err := drv.Delete(context.Background(), badKey); !errors.Is(err, storage.ErrInvalidKey) {
		t.Errorf("Delete() error = %v, want wrapping storage.ErrInvalidKey", err)
	}
	if _, err := drv.Stat(context.Background(), badKey); !errors.Is(err, storage.ErrInvalidKey) {
		t.Errorf("Stat() error = %v, want wrapping storage.ErrInvalidKey", err)
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"NoSuchKey", &types.NoSuchKey{}, true},
		{"NotFound", &types.NotFound{}, true},
		{"other typed error", &types.BucketAlreadyExists{}, false},
		{
			name: "smithy 404 response error",
			err: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 404}},
				Err:      errors.New("not found"),
			},
			want: true,
		},
		{
			name: "smithy 500 response error",
			err: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 500}},
				Err:      errors.New("internal error"),
			},
			want: false,
		},
		{"generic error", errors.New("boom"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotFound(tt.err); got != tt.want {
				t.Errorf("isNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestDriverName_RegisteredAsFactory(t *testing.T) {
	// Registration happens in init(); this only asserts New() rejects
	// a config value of the wrong type, matching how storage.New would
	// call the factory.
	_, err := storage.New(DriverName, "not-an-s3-config")
	if err == nil {
		t.Fatal("storage.New(DriverName, wrong-type) error = nil, want error")
	}
}
