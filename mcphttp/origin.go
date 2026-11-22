package mcphttp

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func checkMCPRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || len(via) >= 10 {
		return errors.New("MCP redirect limit reached")
	}
	if !sameMCPOrigin(via[0].URL, req.URL) {
		return errors.New("MCP redirect must use the configured origin")
	}
	return nil
}

func sameMCPOrigin(base, next *url.URL) bool {
	if next.User != nil || next.Opaque != "" || base.Scheme != next.Scheme ||
		(base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" {
		return false
	}
	return mcpHostname(base) == mcpHostname(next) && mcpPort(base) == mcpPort(next)
}

func mcpHostname(u *url.URL) string {
	host, zone, scoped := strings.Cut(u.Hostname(), "%")
	host = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, host)
	if scoped {
		return host + "%" + zone
	}
	return host
}

func mcpPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
