package trustme_test

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/zoido/trustme-go"
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
	trustme.New(s.T())

	// Then
	// No failure should occur.
}

func (s *CATestSuite) TestCA_CertProperties() {
	// When
	fca := trustme.New(s.T())

	// Then
	s.Require().True(fca.Certificate().IsCA, "Certificate should be CA")
	s.Require().Equal(
		x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
		fca.Certificate().KeyUsage,
		"Certificate should have proper usage set",
	)
}

func (s *CATestSuite) TestCA_CADefaults() {
	// When
	fca := trustme.New(s.T())

	// Then
	s.Require().WithinDuration(
		time.Now(), fca.Certificate().NotBefore, time.Second*5,
		"CA certificate should be valid from about now",
	)
	s.Require().Equal(
		time.Minute, fca.Certificate().NotAfter.Sub(fca.Certificate().NotBefore),
		"CA certificate should be have default TTL",
	)
	s.Require().Equal(
		"trustme-go", fca.Certificate().Subject.CommonName,
		"CA certificate should have default CN",
	)
	s.Require().Equal(
		"trustme-go Org.", fca.Certificate().Subject.Organization[0],
		"CA certificate should have default O",
	)
	s.Require().Equal(2048/8, fca.Key().Size(), "Key should have default size")
}

func (s *CATestSuite) TestCA_WithTTL_Effective() {
	// When
	fca := trustme.New(s.T(), ca.WithTTL(time.Minute*123))

	// Then
	s.Require().Equal(
		time.Minute*123, fca.Certificate().NotAfter.Sub(fca.Certificate().NotBefore),
		"CA certificate should have TTL set via options",
	)
}

func (s *CATestSuite) TestCA_WithRSABits_Effective() {
	// When
	fca := trustme.New(s.T(), ca.WithRSABits(512))

	// Then
	s.Require().Equal(512/8, fca.Key().Size(), "Key should have size set via options")
}

func (s *CATestSuite) TestCA_WithCommonName_Effective() {
	// When
	fca := trustme.New(s.T(), ca.WithCommonName("test-CN"))

	// Then
	s.Require().Equal(
		"test-CN", fca.Certificate().Subject.CommonName,
		"CA certificate should have CN set via options",
	)
}

func (s *CATestSuite) TestCA_WithOrganization_Effective() {
	// When
	fca := trustme.New(s.T(), ca.WithOrganization("Trust Me, Org."))

	// Then
	s.Require().Equal(
		"Trust Me, Org.", fca.Certificate().Subject.Organization[0],
		"CA certificate should have O set via options",
	)
}

func (s *CATestSuite) TestCA_MultipleOptions_Effective() {
	// When
	fca := trustme.New(
		s.T(),
		ca.WithOrganization("Trust Me, Org."),
		ca.WithCommonName("test-CN"),
		ca.WithRSABits(1024),
		ca.WithTTL(time.Minute*123),
	)

	// Then
	s.Require().Equal(
		"Trust Me, Org.", fca.Certificate().Subject.Organization[0],
		"Certificate should have O set via options",
	)
	s.Require().Equal(
		"test-CN", fca.Certificate().Subject.CommonName,
		"Certificate should have CN set via options",
	)
	s.Require().Equal(1024/8, fca.Key().Size(), "Key should have size set via options")
	s.Require().Equal(
		time.Minute*123, fca.Certificate().NotAfter.Sub(fca.Certificate().NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_WithOptions_Effective() {
	// When
	fca := trustme.New(
		s.T(),
		ca.WithOptions(
			ca.WithRSABits(1024),
			ca.WithTTL(time.Minute*123),
		),
	)

	// Then
	s.Require().Equal(1024/8, fca.Key().Size(), "Key should have size set via options")
	s.Require().Equal(
		time.Minute*123, fca.Certificate().NotAfter.Sub(fca.Certificate().NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_Issue_Ok() {
	// Given
	fca := trustme.New(s.T())

	// When
	_ = fca.MustIssue()

	// Then
	// No failure should occur.
}

func (s *CATestSuite) TestCA_Issue_CADefaults() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt := fca.MustIssue()

	// Then
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
	fca := trustme.New(s.T(), ca.WithTTL(time.Minute*123))

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Equal(
		time.Minute*123, crt.Certificate.NotAfter.Sub(crt.Certificate.NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_Issue_DefaultRSaBits_Effective() {
	// Given
	fca := trustme.New(s.T(), ca.WithRSABits(1024))

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Equal(1024/8, crt.Key.Size(), "Key should have size set via options")
}

func (s *CATestSuite) TestCA_Issue_DefaultCommonName_Effective() {
	// Given
	fca := trustme.New(s.T(), ca.WithCommonName("test-CN"))

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Regexp(
		"^test-CN:", crt.Certificate.Subject.CommonName,
		"Certificate should have CN set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_DefaultOrganization_Effective() {
	// Given
	fca := trustme.New(s.T(), ca.WithOrganization("Trust Me, Org."))

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Equal(
		"Trust Me, Org.", crt.Certificate.Subject.Organization[0],
		"Certificate should have O set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_MultipleDefaultOptions_Effective() {
	// Given
	fca := trustme.New(
		s.T(),
		ca.WithRSABits(1024),
		ca.WithTTL(time.Minute*123),
	)

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Equal(1024/8, crt.Key.Size(), "Key should have size set via options")
	s.Require().Equal(
		time.Minute*123, crt.Certificate.NotAfter.Sub(crt.Certificate.NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_Issue_WithOptionsDefalts_Effective() {
	// Given
	fca := trustme.New(
		s.T(),
		ca.WithOptions(
			ca.WithRSABits(1024),
			ca.WithTTL(time.Minute*123),
		),
	)

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Equal(
		time.Minute*123, crt.Certificate.NotAfter.Sub(crt.Certificate.NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_Issue_SerialNumberChanges() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt1 := fca.MustIssue()
	crt2 := fca.MustIssue()

	// Then
	s.Require().Equal(big.NewInt(1000), crt1.Certificate.SerialNumber)
	s.Require().Equal(big.NewInt(1001), crt2.Certificate.SerialNumber)
}
