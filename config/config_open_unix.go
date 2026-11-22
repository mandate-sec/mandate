//go:build unix

// Mandate — Scoped offensive security agent.
// Authorized penetration testing only. Use only with written authorization.
package config

import "syscall"

// Avoid waiting for a FIFO writer before the descriptor can be checked.
const configOpenFlags = syscall.O_NONBLOCK
