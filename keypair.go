package trustme

import (
	"crypto/rsa"
	"crypto/x509"
)

// KeyPair represents server or client certificate
type KeyPair struct {
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

// Certificate returns public certificate of KeyPair.
func (kp *KeyPair) Certificate() *x509.Certificate {
	return kp.certificate
}

// Key returns private key of th KeyPair.
func (kp *KeyPair) Key() *rsa.PrivateKey {
	return kp.privateKey
}
