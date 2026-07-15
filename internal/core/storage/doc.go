// Package storage defines the domain interfaces for uploading and
// retrieving attachment payloads from S3-compatible object storage
// backends (see ADR-007). It must not depend on any adapter-specific
// code (e.g. Postfix milter) — see ADR-002.
package storage
