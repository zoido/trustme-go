<!-- markdownlint-disable MD026 -->
# Trust me. Go!
<!-- markdownlint-enable MD026 -->

[![Go](https://github.com/zoido/trustme-go/workflows/Go/badge.svg)](https://github.com/zoido/trustme-go/actions?query=workflow%3AGo)
[![codecov](https://codecov.io/gh/zoido/trustme-go/branch/master/graph/badge.svg)](https://codecov.io/gh/zoido/trustme-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/zoido/trustme-go)](https://goreportcard.com/report/github.com/zoido/trustme-go)

Inspired by [trustme](https://github.com/python-trio/trustme)
for [Python](https://www.python.org/).

`trustme-go` is a small Go package that offers you with fake
[certificate autority](https://en.wikipedia.org/wiki/Certificate_authority)
(CA) that issues TLS certificates for Go tests for the cases when
[`httptest.NewTLSServer`](https://golang.org/pkg/net/http/httptest/#NewTLSServer)
is not enough.
