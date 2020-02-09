package ca_test

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/zoido/trustme-go/ca"
)

type CATestSuite struct {
	suite.Suite
}

func TestCATestSuite(t *testing.T) {
	suite.Run(t, new(CATestSuite))
}

func (s *CATestSuite) TestCA_Ok() {
	// When
	_, err := ca.New()

	// Then
	s.Require().NoError(err, "Initialization with no options should succeed")
}

func (s *CATestSuite) TestCA_CertProperties() {
	// When
	a, err := ca.New()

	// Then
	s.Require().NoError(err)
	s.Require().True(a.Cert.Certificate.IsCA, "Certificate should be CA")
	s.Require().Equal(
		x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
		a.Cert.Certificate.KeyUsage,
		"Certificate should have proper usage set",
	)
}

func (s *CATestSuite) TestCA_CADefaults() {
	// When
	a, err := ca.New()

	// Then
	s.Require().NoError(err)
	s.Require().WithinDuration(
		time.Now(), a.Cert.Certificate.NotBefore, time.Second*5,
		"CA certificate should be valid from about now",
	)
	s.Require().Equal(
		time.Minute, a.Cert.Certificate.NotAfter.Sub(a.Cert.Certificate.NotBefore),
		"CA certificate should be have default TTL",
	)
	s.Require().Equal(
		"trustme-go", a.Cert.Certificate.Subject.CommonName,
		"CA certificate should have default CN",
	)
	s.Require().Equal(
		"trustme-go Org.", a.Cert.Certificate.Subject.Organization[0],
		"CA certificate should have default O",
	)
	s.Require().Equal(2048/8, a.Cert.Key.Size(), "Key should have default size")
}

func (s *CATestSuite) TestCA_WithTTL_Effective() {
	// When
	a, err := ca.New(ca.WithTTL(time.Minute * 123))

	// Then
	s.Require().NoError(err)
	s.Require().Equal(
		time.Minute*123, a.Cert.Certificate.NotAfter.Sub(a.Cert.Certificate.NotBefore),
		"CA certificate should have TTL set via options",
	)
}

func (s *CATestSuite) TestCA_WithRSABits_Effective() {
	// When
	a, err := ca.New(ca.WithRSABits(512))

	// Then
	s.Require().NoError(err)
	s.Require().Equal(512/8, a.Cert.Key.Size(), "Key should have size set via options")
}

func (s *CATestSuite) TestCA_WithCommonName_Effective() {
	// When
	a, err := ca.New(ca.WithCommonName("test-CN"))

	// Then
	s.Require().NoError(err)
	s.Require().Equal(
		"test-CN", a.Cert.Certificate.Subject.CommonName,
		"CA certificate should have CN set via options",
	)
}

func (s *CATestSuite) TestCA_WithOrganization_Effective() {
	// When
	a, err := ca.New(ca.WithOrganization("Trust Me, Org."))

	// Then
	s.Require().NoError(err)
	s.Require().Equal(
		"Trust Me, Org.", a.Cert.Certificate.Subject.Organization[0],
		"CA certificate should have O set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_Ok() {
	// Given
	a := s.mustCreateCA()

	// When
	_, err := a.Issue()

	// Then
	s.Require().NoError(err, "Issuing with no options should succeed")
}

func (s *CATestSuite) TestCA_Issue_CADefaults() {
	// Given
	a := s.mustCreateCA()

	// When
	crt, err := a.Issue()

	// Then
	s.Require().NoError(err)
	s.Require().WithinDuration(
		time.Now(), crt.Certificate.NotBefore, time.Second*5,
		"Certificate should be valid from about now",
	)
	s.Require().Equal(
		time.Minute, crt.Certificate.NotAfter.Sub(crt.Certificate.NotBefore),
		"Certificate should be have default TTL",
	)
	s.Require().Equal(
		"trustme-go: certificate #1000", crt.Certificate.Subject.CommonName,
		"Certificate should have default CN",
	)
	s.Require().Equal(
		"trustme-go Org.", crt.Certificate.Subject.Organization[0],
		"Certificate should have default O",
	)
	s.Require().Equal(2048/8, crt.Key.Size(), "Key should have default size")
}

func (s *CATestSuite) TestCA_Issue_DefaultTTL_Effective() {
	// Given
	a := s.mustCreateCA(ca.WithTTL(time.Minute * 123))

	// When
	crt, err := a.Issue()

	// Then
	s.Require().NoError(err)
	s.Require().Equal(
		time.Minute*123, crt.Certificate.NotAfter.Sub(crt.Certificate.NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_Issue_DefaultRSaBits_Effective() {
	// Given
	a := s.mustCreateCA(ca.WithRSABits(1024))

	// When
	crt, err := a.Issue()

	// Then
	s.Require().NoError(err)
	s.Require().Equal(1024/8, crt.Key.Size(), "Key should have size set via options")
}

func (s *CATestSuite) TestCA_Issue_DefaultCommonName_Effective() {
	// Given
	a, err := ca.New(ca.WithCommonName("test-CN"))

	// When
	crt, err := a.Issue()

	// Then
	s.Require().NoError(err)
	s.Require().Regexp(
		"^test-CN:", crt.Certificate.Subject.CommonName,
		"Certificate should have CN set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_DefaultOrganization_Effective() {
	// Given
	a, err := ca.New(ca.WithOrganization("Trust Me, Org."))

	// When
	crt, err := a.Issue()

	// Then
	s.Require().NoError(err)
	s.Require().Equal(
		"Trust Me, Org.", crt.Certificate.Subject.Organization[0],
		"Certificate should have O set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_SerialNumberChanges() {
	// Given
	a := s.mustCreateCA()

	// When
	crt1, err1 := a.Issue()
	crt2, err2 := a.Issue()

	// Then
	s.Require().NoError(err1)
	s.Require().NoError(err2)
	s.Require().Equal(big.NewInt(1000), crt1.Certificate.SerialNumber)
	s.Require().Equal(big.NewInt(1001), crt2.Certificate.SerialNumber)
}

func (s *CATestSuite) mustCreateCA(opts ...ca.Option) *ca.CA {
	a, err := ca.New(opts...)
	s.Require().NoError(err, "creating CA under test")
	return a
}
