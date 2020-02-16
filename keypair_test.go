package trustme_test

import (
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

func (s *KeyPairTestSuite) Test_CertificatePEM() {
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

func (s *KeyPairTestSuite) Test_KeyPEM() {
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
