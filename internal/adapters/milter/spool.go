package milter

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// spoolMemThreshold is the number of bytes a message body is allowed
// to occupy in memory before spool spills it to a temporary file on
// disk. This keeps small, common messages fast while still bounding
// worst-case memory use for large ones (SR-115-3).
const spoolMemThreshold = 256 * 1024 // 256 KiB

// spool is a minimal, single-writer-then-single-reader streaming
// buffer for a milter session's message body. It accumulates
// BodyChunk data in memory up to spoolMemThreshold bytes; beyond that
// it spills to a temporary file on disk so the adapter never buffers
// an entire large message in memory (CLAUDE.md invariant #4,
// SR-115-3). It also enforces maxSize, aborting with an error once
// the configured message size limit is exceeded, rather than the
// adapter's own limit machinery.
//
// spool is not safe for concurrent use: a single milter session
// writes to it serially (BodyChunk calls) and reads from it once
// (EndOfMessage), matching how the milter protocol delivers a
// message.
type spool struct {
	maxSize int64

	written int64
	mem     bytes.Buffer
	file    *os.File
}

// newSpool creates a spool that rejects writes once more than
// maxSize bytes have been written in total.
func newSpool(maxSize int64) *spool {
	return &spool{maxSize: maxSize}
}

// errSpoolTooLarge is returned by Write once the cumulative written
// size would exceed the configured maxSize.
var errSpoolTooLarge = fmt.Errorf("milter: message body exceeds configured size limit")

// Write appends chunk to the spool, spilling to a temporary file once
// the in-memory threshold is crossed. It returns errSpoolTooLarge
// (wrapped) if writing chunk would exceed maxSize.
func (s *spool) Write(chunk []byte) (int, error) {
	if s.maxSize > 0 && s.written+int64(len(chunk)) > s.maxSize {
		return 0, fmt.Errorf("%w: limit=%d", errSpoolTooLarge, s.maxSize)
	}

	if s.file == nil && s.mem.Len()+len(chunk) > spoolMemThreshold {
		if err := s.spillToDisk(); err != nil {
			return 0, err
		}
	}

	var (
		n   int
		err error
	)
	if s.file != nil {
		n, err = s.file.Write(chunk)
	} else {
		n, err = s.mem.Write(chunk)
	}
	s.written += int64(n)
	if err != nil {
		return n, fmt.Errorf("milter: spool write: %w", err)
	}
	return n, nil
}

// spillToDisk moves any in-memory contents accumulated so far into a
// newly created temporary file and switches subsequent writes to it.
func (s *spool) spillToDisk() error {
	f, err := os.CreateTemp("", "attachra-milter-body-*.spool")
	if err != nil {
		return fmt.Errorf("milter: spool: create temp file: %w", err)
	}
	if s.mem.Len() > 0 {
		if _, err := f.Write(s.mem.Bytes()); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return fmt.Errorf("milter: spool: write temp file: %w", err)
		}
		s.mem.Reset()
	}
	s.file = f
	return nil
}

// Reader returns a reader over the spool's full contents from the
// beginning. It must only be called once writing has finished (i.e.
// at EndOfMessage). If the spool spilled to disk, this seeks the
// backing file back to the start.
func (s *spool) Reader() (io.Reader, error) {
	if s.file == nil {
		return bytes.NewReader(s.mem.Bytes()), nil
	}
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("milter: spool: seek temp file: %w", err)
	}
	return s.file, nil
}

// Close releases any resources held by the spool (the backing
// temporary file, if one was created), removing the temp file from
// disk. It is safe to call Close multiple times.
func (s *spool) Close() error {
	if s.file == nil {
		return nil
	}
	name := s.file.Name()
	closeErr := s.file.Close()
	removeErr := os.Remove(name)
	s.file = nil
	if closeErr != nil {
		return fmt.Errorf("milter: spool: close temp file: %w", closeErr)
	}
	if removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Errorf("milter: spool: remove temp file: %w", removeErr)
	}
	return nil
}

// Len returns the number of bytes written to the spool so far.
func (s *spool) Len() int64 {
	return s.written
}
