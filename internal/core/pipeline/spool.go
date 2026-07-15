package pipeline

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// spoolMemThreshold bounds how much of a spooled stream is held in
// memory before spilling to a temporary file, mirroring the same
// threshold used by internal/adapters/milter's spool and
// internal/core/rewrite's stageToFile (SR-115-3, CLAUDE.md invariant
// #4): small, common inputs stay fast, while large ones never occupy
// the configured limit's worth of memory in one allocation.
const spoolMemThreshold = 256 * 1024 // 256 KiB

// spool accumulates a stream (the message body, or a single
// attachment's decoded content) up to spoolMemThreshold bytes in
// memory, spilling to a temporary file beyond that. It supports being
// read back multiple times via Reader, which AttachmentProcessor needs
// because both message.Parse (to discover attachments and detect
// their type) and rewrite.Rewrite (to re-walk the MIME tree) must each
// read the complete original message independently — Envelope.Body
// itself is a single-read stream, so it is captured into a spool once
// via spoolReader and re-read from there.
//
// spool is not safe for concurrent use: a caller writes to it once
// (via spoolReader) and may call Reader any number of times afterward,
// but not concurrently with itself.
type spool struct {
	mem  bytes.Buffer
	file *os.File
}

// spoolReader drains all of r into a new *spool, returning an error
// wrapping the underlying read/write failure on failure. On error, any
// partially-written temporary file is cleaned up before returning, so
// no spool temp file is ever leaked on the failure path.
func spoolReader(r io.Reader) (*spool, error) {
	s := &spool{}
	if err := s.readFrom(r); err != nil {
		s.cleanup()
		return nil, err
	}
	return s, nil
}

// readFrom copies r into s, spilling to a temporary file once
// spoolMemThreshold bytes have been buffered in memory.
func (s *spool) readFrom(r io.Reader) error {
	// Read up to the memory threshold directly into mem.
	limited := io.LimitReader(r, spoolMemThreshold)
	if _, err := s.mem.ReadFrom(limited); err != nil {
		return fmt.Errorf("pipeline: spool: buffer to memory: %w", err)
	}
	if s.mem.Len() < spoolMemThreshold {
		// r was fully drained within the memory budget.
		return nil
	}

	// There may be more data: spill to a temp file and continue
	// copying the remainder.
	f, err := os.CreateTemp("", "attachra-pipeline-*.spool")
	if err != nil {
		return fmt.Errorf("pipeline: spool: create temp file: %w", err)
	}
	s.file = f

	if _, err := f.Write(s.mem.Bytes()); err != nil {
		return fmt.Errorf("pipeline: spool: write temp file: %w", err)
	}
	s.mem.Reset()

	if _, err := io.Copy(f, r); err != nil {
		return fmt.Errorf("pipeline: spool: copy remainder to temp file: %w", err)
	}
	return nil
}

// Len returns the total number of bytes captured in the spool.
func (s *spool) Len() int64 {
	if s.file != nil {
		info, err := s.file.Stat()
		if err != nil {
			return 0
		}
		return info.Size()
	}
	return int64(s.mem.Len())
}

// Reader returns a fresh io.Reader over the spool's complete contents
// from the beginning. It may be called more than once (e.g. once for
// message.Parse, once for rewrite.Rewrite), each call yielding an
// independent read from offset zero.
func (s *spool) Reader() (io.Reader, error) {
	if s.file == nil {
		return bytes.NewReader(s.mem.Bytes()), nil
	}
	// Return a fresh *os.File-backed section reader so repeated calls
	// to Reader do not interfere with each other's read position.
	info, err := s.file.Stat()
	if err != nil {
		return nil, fmt.Errorf("pipeline: spool: stat temp file: %w", err)
	}
	return io.NewSectionReader(s.file, 0, info.Size()), nil
}

// cleanup removes the backing temporary file, if any. It is used both
// by spoolReader's error path and by Close.
func (s *spool) cleanup() {
	if s.file == nil {
		return
	}
	name := s.file.Name()
	_ = s.file.Close()
	_ = os.Remove(name)
	s.file = nil
}

// Close releases any resources held by the spool (the backing
// temporary file, if one was created). It is safe to call multiple
// times.
func (s *spool) Close() error {
	if s.file == nil {
		return nil
	}
	name := s.file.Name()
	closeErr := s.file.Close()
	removeErr := os.Remove(name)
	s.file = nil
	if closeErr != nil {
		return fmt.Errorf("pipeline: spool: close temp file: %w", closeErr)
	}
	if removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Errorf("pipeline: spool: remove temp file: %w", removeErr)
	}
	return nil
}
