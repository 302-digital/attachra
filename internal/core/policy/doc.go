// Package policy contains the domain logic for evaluating attachment
// policies against outgoing messages. It must not depend on any
// adapter-specific code (e.g. Postfix milter) — see ADR-002.
package policy
