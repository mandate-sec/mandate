package server

import (
	"fmt"
	"testing"
	"time"
)

func TestPasswordBudgetByPeer(t *testing.T) {
	var l passwordLimiter
	now := time.Unix(100, 0)
	for i := range passwordBurst {
		done, _ := l.begin(fmt.Sprintf("127.0.0.1:%d", i+1), now)
		if done == nil {
			t.Fatal("unexpected rejection", i)
		}
		done()
	}
	if done, retry := l.begin("[::ffff:127.0.0.1]:89", now); done != nil || retry != passwordWindow {
		t.Fatal("a new socket or alternate address notation reset the budget")
	}
	done, _ := l.begin("127.0.0.2:80", now)
	if done == nil {
		t.Fatal("unrelated peer was blocked")
	}
	done()
	done, _ = l.begin("127.0.0.1:80", now.Add(passwordWindow))
	if done == nil {
		t.Fatal("budget did not recover")
	}
	done()
}

func TestPasswordWorkAndMemoryBounded(t *testing.T) {
	var l passwordLimiter
	now := time.Unix(100, 0)
	for i := range passwordConcurrent {
		done, _ := l.begin(fmt.Sprintf("127.0.0.1:%d", i), now)
		if done == nil {
			t.Fatal("early concurrency rejection")
		}
	}
	if done, _ := l.begin("127.0.0.2:80", now); done != nil {
		t.Fatal("too many simultaneous checks")
	}
	for range passwordConcurrent {
		l.finish()
	}
	for i := 1; i < passwordPeerLimit; i++ {
		done, _ := l.begin(fmt.Sprintf("192.0.%d.%d:80", i/256, i%256), now)
		if done == nil {
			t.Fatal("early peer rejection")
		}
		done()
	}
	if done, _ := l.begin("[::1]:80", now); done != nil {
		t.Fatal("peer table exceeded bound")
	}
	done, _ := l.begin("[::1]:80", now.Add(passwordWindow))
	if done == nil || len(l.peers) != 1 {
		t.Fatal("expired peers were not removed")
	}
	done()
}
