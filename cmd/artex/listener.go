package main

import (
	"errors"
	"net"
)

const defaultListenAddr = "127.0.0.1:8787"

func checkListener(address, acknowledgment string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errors.New("expected a listen address with a port")
	}
	if net.ParseIP(host).IsLoopback() || acknowledgment == "yes" {
		return nil
	}
	return errors.New("use a numeric loopback address or explicitly set MANDATE_I_UNDERSTAND_THIS_IS_DANGEROUS=yes")
}
