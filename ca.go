package trustme

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/zoido/trustme-go/ca"
	"github.com/zoido/trustme-go/cert"
)

// CA is a fake certification authority for issuing TLS certificates for tests.
// It wraps the ca.CA and provides the "errorless" interface where the test fails when
// the method would return error.
type CA struct {
	ca *ca.CA
	t  *testing.T
}

// New returns new instance of th CA and fails the test when creation fails.
func New(t *testing.T, options ...ca.Option) *CA {
	c, err := ca.New(options...)

	if err != nil {
		t.Error(err)
	}

	return &CA{
		ca: c,
		t:  t,
	}
}

// Certificate returns public certificate of underlying fake CA.
func (fca *CA) Certificate() *x509.Certificate {
	return fca.ca.Cert.Certificate
}

// Key returns private key of underlying fake CA.
func (fca *CA) Key() *rsa.PrivateKey {
	return fca.ca.Cert.Key
}

// MustIssue issues new certificate signed by the CA. Fails the test
func (fca *CA) MustIssue(options ...cert.Option) *cert.LeafCert {
	lc, err := fca.ca.Issue(options...)
	fca.checkError(err)
	return lc
}

func (fca *CA) checkError(err error) {
	if err != nil {
		fca.t.Error(err)
	}
}
