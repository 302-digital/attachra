package s3

import (
	"context"
	"os"
	"testing"

	"github.com/302-digital/attachra/internal/core/storage"
	"github.com/302-digital/attachra/internal/core/storage/storagetest"
)

// TestDriver_ContractSuite_MinIO runs the full storage contract suite
// (ATR-177, ATR-174) against a real S3-compatible service, so the
// driver's behavior is verified against actual wire semantics, not
// just local unit assumptions.
//
// It requires ATTACHRA_TEST_S3_ENDPOINT to be set (e.g.
// "http://localhost:9000" for the MinIO instance started by
// deploy/dev/docker-compose.yml) and is skipped otherwise — this
// environment does not have Docker available, so it has not been run
// here; run it on a host with Docker (see deploy/dev/docker-compose.yml
// and deploy/dev/attachra.yaml for the matching bucket/credentials).
//
// Credentials and bucket default to the deploy/dev/docker-compose.yml
// values (MINIO_ROOT_USER=attachra-dev, MINIO_ROOT_PASSWORD=attachra-dev-secret,
// bucket "attachra-dev") but can be overridden via
// ATTACHRA_TEST_S3_ACCESS_KEY / ATTACHRA_TEST_S3_SECRET_KEY /
// ATTACHRA_TEST_S3_BUCKET / ATTACHRA_TEST_S3_REGION for other MinIO/S3
// setups.
func TestDriver_ContractSuite_MinIO(t *testing.T) {
	endpoint := os.Getenv("ATTACHRA_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("ATTACHRA_TEST_S3_ENDPOINT not set; skipping MinIO integration test (see deploy/dev/docker-compose.yml)")
	}

	cfg := Config{
		Endpoint:  endpoint,
		Region:    getenvDefault("ATTACHRA_TEST_S3_REGION", "us-east-1"),
		Bucket:    getenvDefault("ATTACHRA_TEST_S3_BUCKET", "attachra-dev"),
		AccessKey: getenvDefault("ATTACHRA_TEST_S3_ACCESS_KEY", "attachra-dev"),
		SecretKey: getenvDefault("ATTACHRA_TEST_S3_SECRET_KEY", "attachra-dev-secret"),
		PathStyle: true,
	}

	drv, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}

	storagetest.Run(t, drv, func() string {
		key, err := storage.NewObjectKey()
		if err != nil {
			t.Fatalf("NewObjectKey() error = %v", err)
		}
		return key
	})
}

func getenvDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
