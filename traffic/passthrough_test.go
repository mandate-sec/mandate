package traffic

import "testing"

func TestCaptureRequiresUpstreamCertificateVerification(t *testing.T) {
	tr, _ := openTraffic(t)
	if tr.proxy.Opts.SslInsecure {
		t.Fatal("recording proxy would accept an untrusted upstream certificate")
	}
}
