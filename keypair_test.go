package trustme_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zoido/trustme-go"
)

func TestCertificatePEM(t *testing.T) {
	// Given
	ca := trustme.New(t)
	kp := ca.MustIssue(trustme.WithCommonName("TESTING CERTIFICATE"))

	// When
	c := kp.CertificatePEM()

	// Then
	block, _ := pem.Decode(c)
	require.NotNil(t, block, "Result data has to be de-codable as PEM")
	require.Equal(t, "CERTIFICATE", block.Type, "Decoded type has tu be CERTIFICATE")
	crt, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Result data has to be parsable as x509 certificate again")
	require.Equal(t, "TESTING CERTIFICATE", crt.Subject.CommonName)
}

func TestKeyPEM(t *testing.T) {
	// Given
	ca := trustme.New(t)
	kp := ca.MustIssue()

	// When
	c := kp.KeyPEM()

	// Then
	block, _ := pem.Decode(c)
	require.NotNil(t, block, "Result data has to be de-codable as PEM")
	require.Equal(t, "RSA PRIVATE KEY", block.Type, "Decoded type has tu be RSA PRIVATE KEY")
	_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err, "Result data has to be parsable as x509 private key again")
}

func TestAsX509KeyPair(t *testing.T) {
	// Given
	ca := trustme.New(t)
	kp := ca.MustIssue()

	// When
	c := kp.AsX509KeyPair()

	// Then
	require.Equal(t, kp.Key(), c.PrivateKey)
	require.Equal(t, kp.Certificate().Raw, c.Certificate[0])
}

func TestAsServerConfig(t *testing.T) {
	// Given
	ca := trustme.New(t)
	kp := ca.MustIssue()

	// When
	cfg := kp.AsServerConfig()

	// Then
	require.Equal(t, ca.CertPool(), cfg.ClientCAs)
	require.Equal(t, []tls.Certificate{kp.AsX509KeyPair()}, cfg.Certificates)
}

func TestAsClientConfig(t *testing.T) {
	// Given
	ca := trustme.New(t)
	kp := ca.MustIssue()

	// When
	cfg := kp.AsClientConfig()

	// Then
	require.Equal(t, ca.CertPool(), cfg.RootCAs)
	require.Equal(t, []tls.Certificate{kp.AsX509KeyPair()}, cfg.Certificates)
}
