package trustme_test

import (
	"crypto/x509"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/zoido/trustme-go"
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
	s.Require().True(fca.Certificate().IsCA, "CA certificate should be CA")
	s.Require().Equal(
		x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
		fca.Certificate().KeyUsage,
		"CA certificate should have proper usage set",
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
	fca := trustme.New(s.T(), trustme.WithTTL(time.Minute*123))

	// Then
	s.Require().Equal(
		time.Minute*123, fca.Certificate().NotAfter.Sub(fca.Certificate().NotBefore),
		"CA certificate should have TTL set via options",
	)
}

func (s *CATestSuite) TestCA_WithRSABits_Effective() {
	// When
	fca := trustme.New(s.T(), trustme.WithRSABits(512))

	// Then
	s.Require().Equal(512/8, fca.Key().Size(), "CA key should have size set via options")
}

func (s *CATestSuite) TestCA_WithCommonName_Effective() {
	// When
	fca := trustme.New(s.T(), trustme.WithCommonName("test-CN"))

	// Then
	s.Require().Equal(
		"test-CN", fca.Certificate().Subject.CommonName,
		"CA certificate should have CN set via options",
	)
}

func (s *CATestSuite) TestCA_WithOrganization_Effective() {
	// When
	fca := trustme.New(s.T(), trustme.WithOrganization("Trust Me, Org."))

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
		trustme.WithOrganization("Trust Me, Org."),
		trustme.WithCommonName("test-CN"),
		trustme.WithRSABits(1024),
		trustme.WithTTL(time.Minute*123),
	)

	// Then
	s.Require().Equal(
		"Trust Me, Org.", fca.Certificate().Subject.Organization[0],
		"CA certificate should have O set via options",
	)
	s.Require().Equal(
		"test-CN", fca.Certificate().Subject.CommonName,
		"CA certificate should have CN set via options",
	)
	s.Require().Equal(1024/8, fca.Key().Size(), "CA key should have size set via options")
	s.Require().Equal(
		time.Minute*123, fca.Certificate().NotAfter.Sub(fca.Certificate().NotBefore),
		"CA certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_CertPool() {
	// Given
	cn := "TESTING CA"
	o := "Testing Organization"
	fca := trustme.New(
		s.T(),
		trustme.WithCommonName(cn),
		trustme.WithOrganization(o),
	)

	// When
	pool := fca.CertPool()

	// Then
	s.Require().Len(pool.Subjects(), 1, "CertPool needs to obtain only the CA's certificate")
	s.Require().Equal(fca.Certificate().RawSubject, pool.Subjects()[0])
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
		time.Now(), crt.Certificate().NotBefore, time.Second*5,
		"Certificate should be valid from about now",
	)
	s.Require().Equal(
		time.Minute, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should be have default TTL",
	)
	s.Require().Equal(
		"trustme-go: certificate #1000", crt.Certificate().Subject.CommonName,
		"Certificate should have default CN",
	)
	s.Require().Equal(
		"trustme-go Org.", crt.Certificate().Subject.Organization[0],
		"Certificate should have default O",
	)
	s.Require().Equal(2048/8, crt.Key().Size(), "Key should have default size")
}

func (s *CATestSuite) TestCA_Issue_DefaultTTL_Effective() {
	// Given
	fca := trustme.New(s.T(), trustme.WithTTL(time.Minute*123))

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Equal(
		time.Minute*123, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_Issue_DefaultRSaBits_Effective() {
	// Given
	fca := trustme.New(s.T(), trustme.WithRSABits(1024))

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Equal(1024/8, crt.Key().Size(), "Key should have size set via options")
}

func (s *CATestSuite) TestCA_Issue_DefaultCommonName_Effective() {
	// Given
	fca := trustme.New(s.T(), trustme.WithCommonName("test-CN"))

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Regexp(
		"^test-CN:", crt.Certificate().Subject.CommonName,
		"Certificate should have CN set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_DefaultOrganization_Effective() {
	// Given
	fca := trustme.New(s.T(), trustme.WithOrganization("Trust Me, Org."))

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Equal(
		"Trust Me, Org.", crt.Certificate().Subject.Organization[0],
		"Certificate should have O set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_MultipleDefaultOptions_Effective() {
	// Given
	fca := trustme.New(
		s.T(),
		trustme.WithRSABits(1024),
		trustme.WithTTL(time.Minute*123),
	)

	// When
	crt := fca.MustIssue()

	// Then
	s.Require().Equal(1024/8, crt.Key().Size(), "Key should have size set via options")
	s.Require().Equal(
		time.Minute*123, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_Issue_WithTTL_Effective() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt := fca.MustIssue(trustme.WithTTL(time.Hour * 123))

	// Then
	s.Require().Equal(
		time.Hour*123, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should have TTL set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_WithRSABits_Effective() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt := fca.MustIssue(trustme.WithRSABits(1024))

	// Then
	s.Require().Equal(1024/8, crt.Key().Size(), "Key should have size set via options")
}

func (s *CATestSuite) TestCA_Issue_WithCommonName_Effective() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt := fca.MustIssue(trustme.WithCommonName("cert-test-CN"))

	// Then
	s.Require().Equal(
		"cert-test-CN", crt.Certificate().Subject.CommonName,
		"Certificate should have CN set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_MultipleOptions_Effective() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt := fca.MustIssue(
		trustme.WithRSABits(1024),
		trustme.WithTTL(time.Minute*123),
	)

	// Then
	s.Require().Equal(1024/8, crt.Key().Size(), "Key should have size set via options")
	s.Require().Equal(
		time.Minute*123, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func (s *CATestSuite) TestCA_Issue_WithDNS_Effective() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt := fca.MustIssue(
		trustme.WithDNS("dns.a"),
		trustme.WithDNS("dns.b"),
	)

	// Then
	s.Require().ElementsMatch(
		crt.Certificate().DNSNames, []string{"dns.a", "dns.b"},
		"Certificate should have DNS names SAN set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_WithIP_Effective() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt := fca.MustIssue(
		trustme.WithIP(net.IPv6loopback),
		trustme.WithIP(net.IPv4(8, 8, 8, 8)),
		trustme.WithIP(net.IPv4(127, 0, 0, 1)),
	)

	// Then
	certIPs := make([]string, 0, len(crt.Certificate().IPAddresses))
	for _, ip := range crt.Certificate().IPAddresses {
		certIPs = append(certIPs, ip.String())
	}
	s.Require().ElementsMatch(
		certIPs, []string{"8.8.8.8", "127.0.0.1", "::1"},
		"Certificate should have IP addresses names SAN set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_WithEmail_Effective() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt := fca.MustIssue(
		trustme.WithEmail("example@example.com"),
		trustme.WithEmail("test@example.com"),
	)

	// Then
	s.Require().ElementsMatch(
		crt.Certificate().EmailAddresses, []string{"example@example.com", "test@example.com"},
		"Certificate should have email addresses names SAN set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_WithURI_Effective() {
	// Given
	fca := trustme.New(s.T())

	uri1 := &url.URL{
		Scheme: "https",
		Host:   "example.com",
		Path:   "/test/path",
	}
	uri2 := &url.URL{
		Scheme: "spiffe",
		Host:   "trust.domain",
		Path:   "/test/path",
	}

	// When
	crt := fca.MustIssue(
		trustme.WithURI(uri1),
		trustme.WithURI(uri2),
	)

	// Then
	s.Require().ElementsMatch(
		crt.Certificate().URIs, []*url.URL{uri1, uri2},
		"Certificate should have email addresses names SAN set via options",
	)
}

func (s *CATestSuite) TestCA_Issue_SerialNumberChanges() {
	// Given
	fca := trustme.New(s.T())

	// When
	crt1 := fca.MustIssue()
	crt2 := fca.MustIssue()

	// Then
	s.Require().Equal(big.NewInt(1000), crt1.Certificate().SerialNumber)
	s.Require().Equal(big.NewInt(1001), crt2.Certificate().SerialNumber)
}
