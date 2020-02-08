package trustme

import (
	"testing"

	"github.com/zoido/trustme-go/ca"
)

// CA is a fake certification authority for issuing TLS certificates for tests.
type CA struct {
	ca      *ca.CA
	testing *testing.T
}

// MustCreateNewCA returns new instance of th CA and fails the test when creation fails.
func MustCreateNewCA(t *testing.T, options ...ca.Option) *CA {
	c, err := ca.New(options...)

	if err != nil {
		testing.Error(err)
	}

	return &CA{
		ca:      c,
		testing: t,
	}
}
