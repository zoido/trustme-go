package trustme_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/zoido/trustme-go"
)

type KeyPairTestSuite struct {
	suite.Suite
}

func TestKeyPairTestSuite(t *testing.T) {
	suite.Run(t, new(KeyPairTestSuite))
}

func (s *KeyPairTestSuite) TestCertificatePEM() {
	// Given
	ca := trustme.New(s.T())
	kp := ca.MustIssue(trustme.WithCommonName("TESTING CERTIFICATE"))

	// When
	c := kp.CertificatePEM()

	// Then
	block, _ := pem.Decode(c)
	s.Require().NotNil(block, "Result data has to be de-codable as PEM")
	s.Require().Equal("CERTIFICATE", block.Type, "Decoded type has tu be CERTIFICATE")
	crt, err := x509.ParseCertificate(block.Bytes)
	s.Require().NoError(err, "Result data has to be parsable as x509 certificate again")
	s.Require().Equal("TESTING CERTIFICATE", crt.Subject.CommonName)
}

func (s *KeyPairTestSuite) TestKeyPEM() {
	// Given
	ca := trustme.New(s.T())
	kp := ca.MustIssue()

	// When
	c := kp.KeyPEM()

	// Then
	block, _ := pem.Decode(c)
	s.Require().NotNil(block, "Result data has to be de-codable as PEM")
	s.Require().Equal("RSA PRIVATE KEY", block.Type, "Decoded type has tu be RSA PRIVATE KEY")
	_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	s.Require().NoError(err, "Result data has to be parsable as x509 private key again")
}

func (s *KeyPairTestSuite) TestAsX509KeyPair() {
	// Given
	ca := trustme.New(s.T())
	kp := ca.MustIssue()

	// When
	c := kp.AsX509KeyPair()

	// Then
	s.Require().Equal(kp.Key(), c.PrivateKey)
	s.Require().Equal(kp.Certificate().Raw, c.Certificate[0])
}

func (s *KeyPairTestSuite) TestAsServerConfig() {
	// Given
	ca := trustme.New(s.T())
	kp := ca.MustIssue()

	// When
	cfg := kp.AsServerConfig()

	// Then
	s.Require().Equal(ca.CertPool(), cfg.ClientCAs)
	s.Require().Equal([]tls.Certificate{kp.AsX509KeyPair()}, cfg.Certificates)
}

func (s *KeyPairTestSuite) TestAsClientConfig() {
	// Given
	ca := trustme.New(s.T())
	kp := ca.MustIssue()

	// When
	cfg := kp.AsClientConfig()

	// Then
	s.Require().Equal(ca.CertPool(), cfg.RootCAs)
	s.Require().Equal([]tls.Certificate{kp.AsX509KeyPair()}, cfg.Certificates)
}
