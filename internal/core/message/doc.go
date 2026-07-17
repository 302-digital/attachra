// Package message implements streaming parsing of outgoing email
// messages to reliably enumerate every attachment (inline and
// attachment-disposition) regardless of MIME tree shape, including
// nested message/rfc822 parts.
//
// It must not depend on any adapter-specific code (e.g. Postfix
// milter) — see ADR-002. The parser never buffers the whole message
// in memory: parts are read and their content walked as streams, and
// callers control how much of each part's body is read via Attachment
// (see ATR-117 / US-3.1 and the streaming invariant).
package message
