// Package s3 implements storage.Driver on top of an S3-compatible
// object storage service using aws-sdk-go-v2 (US-5.1, ATR-173). It
// works against both AWS S3 and MinIO (path-style addressing).
//
// Security posture (SR-121-1): this driver never sets a public/canned
// ACL on objects and never generates presigned URLs. All object
// access in the MVP goes through Attachra's own download endpoint,
// which reads bytes via Get and streams them to the recipient; the
// bucket and its objects are expected to be otherwise fully private.
//
// Client-side encryption (SR-121-2 follow-up): Put/Get currently only
// support server-side encryption via Config.SSE (SSE-S3/SSE-KMS
// headers on PutObject). A future client-side encryption layer (e.g.
// encrypting the plaintext before it reaches this driver, or wrapping
// r in Put/the returned io.ReadCloser in Get with an
// encrypt/decrypt stream) can be added without changing the
// storage.Driver contract: it would live either as a wrapping
// storage.Driver decorator or inside this package as an additional
// Config option. This package intentionally does not block that
// extension point by, e.g., assuming the stored byte length always
// equals the plaintext length elsewhere in the codebase.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/302-digital/attachra/internal/core/storage"
)

// DriverName is the name this driver registers itself under via
// storage.Register, and the expected value of config.StorageConfig.Driver
// to select it.
const DriverName = "s3"

func init() {
	storage.Register(DriverName, func(cfg any) (storage.Driver, error) {
		c, ok := cfg.(Config)
		if !ok {
			return nil, fmt.Errorf("s3: New: expected s3.Config, got %T", cfg)
		}
		return New(context.Background(), c)
	})
}

// Config configures the S3-compatible storage driver. It mirrors
// internal/config.S3Config field-for-field; the config package
// constructs a Config value of this shape when wiring up the driver
// via storage.New(DriverName, cfg).
type Config struct {
	// Endpoint is the S3-compatible service endpoint URL (e.g.
	// "http://localhost:9000" for MinIO). Empty uses the AWS SDK's
	// default endpoint resolution for Region.
	Endpoint string

	// Region is the AWS region (or a placeholder such as
	// "us-east-1" for MinIO).
	Region string

	// Bucket is the bucket objects are stored in.
	Bucket string

	// AccessKey and SecretKey are static credentials. If either is
	// empty, the AWS SDK's default credential chain is used.
	AccessKey string
	SecretKey string

	// PathStyle forces path-style bucket addressing, required by
	// MinIO and most non-AWS S3-compatible services.
	PathStyle bool

	// SSE selects server-side encryption applied on Put (SR-121-2):
	// "" (none), "AES256" (SSE-S3), or "aws:kms" (SSE-KMS).
	SSE string

	// SSEKMSKeyID is the KMS key ID/ARN used when SSE is "aws:kms".
	SSEKMSKeyID string
}

// Driver implements storage.Driver against an S3-compatible service.
type Driver struct {
	client *s3.Client
	bucket string
	sse    types.ServerSideEncryption
	kmsKey string
}

// New constructs an S3 Driver from cfg. It never sets a public ACL
// and never issues presigned URLs (SR-121-1) — every method call goes
// directly through the AWS SDK's client to the S3-compatible service.
func New(ctx context.Context, cfg Config) (*Driver, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3: bucket must not be empty")
	}
	if cfg.Region == "" {
		return nil, errors.New("s3: region must not be empty")
	}

	var optFns []func(*awsconfig.LoadOptions) error
	optFns = append(optFns, awsconfig.WithRegion(cfg.Region))
	if cfg.AccessKey != "" || cfg.SecretKey != "" {
		optFns = append(optFns, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("s3: load AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = &cfg.Endpoint
		}
		o.UsePathStyle = cfg.PathStyle
	})

	sse, err := parseSSE(cfg.SSE)
	if err != nil {
		return nil, err
	}

	return &Driver{
		client: client,
		bucket: cfg.Bucket,
		sse:    sse,
		kmsKey: cfg.SSEKMSKeyID,
	}, nil
}

// parseSSE validates and converts the configured SSE mode string into
// the SDK's enum, returning an empty types.ServerSideEncryption for
// "" (no SSE header sent on Put).
func parseSSE(mode string) (types.ServerSideEncryption, error) {
	switch mode {
	case "":
		return "", nil
	case string(types.ServerSideEncryptionAes256):
		return types.ServerSideEncryptionAes256, nil
	case string(types.ServerSideEncryptionAwsKms):
		return types.ServerSideEncryptionAwsKms, nil
	default:
		return "", fmt.Errorf("s3: unsupported sse mode %q (want \"\", %q, or %q)", mode, types.ServerSideEncryptionAes256, types.ServerSideEncryptionAwsKms)
	}
}

// Put implements storage.Driver. It streams r directly into a single
// PutObject call — no public ACL is ever set (SR-121-1) — applying
// the configured server-side encryption, if any (SR-121-2).
func (d *Driver) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := storage.ValidateKey(key); err != nil {
		return fmt.Errorf("s3: %s: %w", key, err)
	}

	input := &s3.PutObjectInput{
		Bucket:        &d.bucket,
		Key:           &key,
		Body:          r,
		ContentLength: &size,
	}
	if d.sse != "" {
		input.ServerSideEncryption = d.sse
		if d.sse == types.ServerSideEncryptionAwsKms && d.kmsKey != "" {
			input.SSEKMSKeyId = &d.kmsKey
		}
	}

	if _, err := d.client.PutObject(ctx, input); err != nil {
		return fmt.Errorf("s3: put %q: %w", key, err)
	}
	return nil
}

// Get implements storage.Driver, returning a stream over the
// object's contents without buffering it in memory. This driver never
// generates a presigned URL for the caller to fetch the object
// directly (SR-121-1); bytes always flow through this process.
func (d *Driver) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := storage.ValidateKey(key); err != nil {
		return nil, fmt.Errorf("s3: %s: %w", key, err)
	}

	out, err := d.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &d.bucket,
		Key:    &key,
	})
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("s3: %s: %w", key, storage.ErrNotFound)
		}
		return nil, fmt.Errorf("s3: get %q: %w", key, err)
	}
	return out.Body, nil
}

// Delete implements storage.Driver.
func (d *Driver) Delete(ctx context.Context, key string) error {
	if err := storage.ValidateKey(key); err != nil {
		return fmt.Errorf("s3: %s: %w", key, err)
	}

	if _, err := d.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &d.bucket,
		Key:    &key,
	}); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("s3: %s: %w", key, storage.ErrNotFound)
		}
		return fmt.Errorf("s3: delete %q: %w", key, err)
	}
	return nil
}

// Stat implements storage.Driver via HeadObject, never reading the
// object's contents.
func (d *Driver) Stat(ctx context.Context, key string) (storage.ObjectInfo, error) {
	if err := storage.ValidateKey(key); err != nil {
		return storage.ObjectInfo{}, fmt.Errorf("s3: %s: %w", key, err)
	}

	out, err := d.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &d.bucket,
		Key:    &key,
	})
	if err != nil {
		if isNotFound(err) {
			return storage.ObjectInfo{}, fmt.Errorf("s3: %s: %w", key, storage.ErrNotFound)
		}
		return storage.ObjectInfo{}, fmt.Errorf("s3: stat %q: %w", key, err)
	}

	var size int64
	if out.ContentLength != nil {
		size = *out.ContentLength
	}
	return storage.ObjectInfo{Key: key, Size: size}, nil
}

// Ping is a lightweight readiness probe (US-7.2/T-7.2.3, ATR-194): a
// HeadBucket call confirms the configured bucket is reachable and
// accessible with the driver's credentials, without reading or writing
// any object. It is not part of storage.Driver's interface;
// internal/adapters/http's readiness handler type-asserts for this
// method opportunistically (see its storagePinger interface).
func (d *Driver) Ping(ctx context.Context) error {
	if _, err := d.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &d.bucket}); err != nil {
		return fmt.Errorf("s3: ping bucket %q: %w", d.bucket, err)
	}
	return nil
}

// isNotFound reports whether err represents an S3 "object does not
// exist" response, across the several shapes the SDK/service may
// return it as: a typed *types.NoSuchKey (GetObject), a typed
// *types.NotFound (HeadObject on some services), or a generic HTTP
// 404 wrapped in *smithyhttp.ResponseError (observed from some
// S3-compatible services, including MinIO, for DeleteObject/HeadObject).
func isNotFound(err error) bool {
	var noSuchKey *types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return true
	}
	var notFound *types.NotFound
	if errors.As(err, &notFound) {
		return true
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
		return true
	}
	return false
}
