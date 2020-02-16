<!-- markdownlint-disable MD026 -->

# Trust me. Go!

<!-- markdownlint-enable MD026 -->

[![Go](https://github.com/zoido/trustme-go/workflows/Go/badge.svg)](https://github.com/zoido/trustme-go/actions?query=workflow%3AGo)
[![codecov](https://codecov.io/gh/zoido/trustme-go/branch/master/graph/badge.svg)](https://codecov.io/gh/zoido/trustme-go)
[![GoDoc](https://godoc.org/github.com/zoido/trustme-go?status.svg)](https://godoc.org/github.com/zoido/trustme-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/zoido/trustme-go)](https://goreportcard.com/report/github.com/zoido/trustme-go)

Inspired by [trustme](https://github.com/python-trio/trustme)
for [Python](https://www.python.org/).

`trustme-go` is a small Go package that offers you with fake
[certificate autority](https://en.wikipedia.org/wiki/Certificate_authority)
(CA) that issues TLS certificates for Go tests for the cases when
[`httptest.NewTLSServer`](https://golang.org/pkg/net/http/httptest/#NewTLSServer)
is not enough.

## Example

<!-- markdownlint-disable MD010 -->

```go
func TestExample(t *testing.T) {
	ca := trustme.New(t)

	srvCfg := ca.MustIssue(trustme.WithIP(net.ParseIP("127.0.0.1"))).AsServerConfig()
	srvCfg.ClientAuth = tls.RequireAndVerifyClientCert
	listener, _ := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	defer listener.Close()

	srv := http.Server{
		Handler: http.HandlerFunc(ExampleHandler),
	}
	defer srv.Close()
	go srv.Serve(listener)

    client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: ca.MustIssue().AsClientConfig(),
		},
		Timeout: time.Second * 5,
    }

	client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
}

```

<!-- markdownlint-enable MD010 -->
