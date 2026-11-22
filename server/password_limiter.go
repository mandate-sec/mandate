package server

import (
	"net/netip"
	"sync"
	"time"
)

const (
	passwordWindow     = time.Minute
	passwordBurst      = 10
	passwordPeerLimit  = 1024
	passwordConcurrent = 2
)

type passwordWindowEntry struct {
	expires time.Time
	count   int
}

type passwordLimiter struct {
	mu        sync.Mutex
	peers     map[netip.Addr]passwordWindowEntry
	active    int
	nextSweep time.Time
}

// Only the transport peer identifies a budget. Client-supplied headers cannot reset it.
func (l *passwordLimiter) begin(remote string, now time.Time) (done func(), retry time.Duration) {
	endpoint, _ := netip.ParseAddrPort(remote)
	peer := endpoint.Addr().Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= passwordConcurrent {
		return nil, time.Second
	}
	if l.peers == nil {
		l.peers = make(map[netip.Addr]passwordWindowEntry)
	}
	if !now.Before(l.nextSweep) {
		for addr, entry := range l.peers {
			if !now.Before(entry.expires) {
				delete(l.peers, addr)
			}
		}
		l.nextSweep = now.Add(time.Second)
	}
	entry, exists := l.peers[peer]
	if !exists && len(l.peers) >= passwordPeerLimit {
		return nil, time.Second
	}
	if !now.Before(entry.expires) {
		entry = passwordWindowEntry{expires: now.Add(passwordWindow)}
	}
	if entry.count >= passwordBurst {
		return nil, entry.expires.Sub(now)
	}
	entry.count++
	l.peers[peer] = entry
	l.active++
	return l.finish, 0
}

func (l *passwordLimiter) finish() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
}
