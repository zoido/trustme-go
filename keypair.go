package trustme

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"testing"
)

// KeyPair represents server or client certificate.
type KeyPair struct {
	t         *testing.T
	authority *Authority

	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

// Certificate returns public certificate of the KeyPair.
func (kp *KeyPair) Certificate() *x509.Certificate {
	return kp.certificate
}

// Key returns private key of the KeyPair.
func (kp *KeyPair) Key() *rsa.PrivateKey {
	return kp.privateKey
}

// KeyPEM returns PEM encoded KeyPair's private key.
func (kp *KeyPair) KeyPEM() []byte {
	var buff bytes.Buffer
	w := io.Writer(&buff)
	err := pem.Encode(
		w,
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(kp.privateKey)})
	if err != nil {
		kp.t.Error(fmt.Errorf("PEM encoding KeyPair's private key: %w", err))
	}
	return buff.Bytes()
}

// CertificatePEM returns PEM encoded KeyPair's certificate.
func (kp *KeyPair) CertificatePEM() []byte {
	var buff bytes.Buffer
	w := io.Writer(&buff)
	err := pem.Encode(
		w,
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: kp.certificate.Raw})
	if err != nil {
		kp.t.Error(fmt.Errorf("PEM encoding KeyPair's certificate: %w", err))
	}
	return buff.Bytes()
}
