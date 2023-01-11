package trustme_test

import (
	"crypto/x509"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zoido/trustme-go"
)

func TestCA_Ok(t *testing.T) {
	// When
	trustme.New(t)

	// Then
	// No failure should occur.
}

func TestCA_CertProperties(t *testing.T) {
	// When
	fca := trustme.New(t)

	// Then
	require.True(t, fca.Certificate().IsCA, "CA certificate should be CA")
	require.Equal(t,
		x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
		fca.Certificate().KeyUsage,
		"CA certificate should have proper usage set",
	)
}

func TestCA_CADefaults(t *testing.T) {
	// When
	fca := trustme.New(t)

	// Then
	require.WithinDuration(t,
		time.Now(), fca.Certificate().NotBefore, time.Second*5,
		"CA certificate should be valid from about now",
	)
	require.Equal(t,
		time.Minute, fca.Certificate().NotAfter.Sub(fca.Certificate().NotBefore),
		"CA certificate should be have default TTL",
	)
	require.Equal(t,
		"trustme-go", fca.Certificate().Subject.CommonName,
		"CA certificate should have default CN",
	)
	require.Equal(t,
		"trustme-go Org.", fca.Certificate().Subject.Organization[0],
		"CA certificate should have default O",
	)
	require.Equal(t, 2048/8, fca.Key().Size(), "Key should have default size")
}

func TestCA_WithTTL_Effective(t *testing.T) {
	// When
	fca := trustme.New(t, trustme.WithTTL(time.Minute*123))

	// Then
	require.Equal(t,
		time.Minute*123, fca.Certificate().NotAfter.Sub(fca.Certificate().NotBefore),
		"CA certificate should have TTL set via options",
	)
}

func TestCA_WithRSABits_Effective(t *testing.T) {
	// When
	fca := trustme.New(t, trustme.WithRSABits(512))

	// Then
	require.Equal(t, 512/8, fca.Key().Size(), "CA key should have size set via options")
}

func TestCA_WithCommonName_Effective(t *testing.T) {
	// When
	fca := trustme.New(t, trustme.WithCommonName("test-CN"))

	// Then
	require.Equal(t,
		"test-CN", fca.Certificate().Subject.CommonName,
		"CA certificate should have CN set via options",
	)
}

func TestCA_WithOrganization_Effective(t *testing.T) {
	// When
	fca := trustme.New(t, trustme.WithOrganization("Trust Me, Org."))

	// Then
	require.Equal(t,
		"Trust Me, Org.", fca.Certificate().Subject.Organization[0],
		"CA certificate should have O set via options",
	)
}

func TestCA_MultipleOptions_Effective(t *testing.T) {
	// When
	fca := trustme.New(
		t,
		trustme.WithOrganization("Trust Me, Org."),
		trustme.WithCommonName("test-CN"),
		trustme.WithRSABits(1024),
		trustme.WithTTL(time.Minute*123),
	)

	// Then
	require.Equal(t,
		"Trust Me, Org.", fca.Certificate().Subject.Organization[0],
		"CA certificate should have O set via options",
	)
	require.Equal(t,
		"test-CN", fca.Certificate().Subject.CommonName,
		"CA certificate should have CN set via options",
	)
	require.Equal(t, 1024/8, fca.Key().Size(), "CA key should have size set via options")
	require.Equal(t,
		time.Minute*123, fca.Certificate().NotAfter.Sub(fca.Certificate().NotBefore),
		"CA certificate should have TTL set via CA options",
	)
}

func TestCA_CertPool(t *testing.T) {
	// Given
	cn := "TESTING CA"
	o := "Testing Organization"
	fca := trustme.New(
		t,
		trustme.WithCommonName(cn),
		trustme.WithOrganization(o),
	)

	// When
	pool := fca.CertPool()

	// Then
	require.Len(t, pool.Subjects(), 1, "CertPool needs to obtain only the CA's certificate")
	require.Equal(t, fca.Certificate().RawSubject, pool.Subjects()[0])
}

func TestCA_Issue_Ok(t *testing.T) {
	// Given
	fca := trustme.New(t)

	// When
	_ = fca.MustIssue()

	// Then
	// No failure should occur.
}

func TestCA_Issue_CADefaults(t *testing.T) {
	// Given
	fca := trustme.New(t)

	// When
	crt := fca.MustIssue()

	// Then
	require.WithinDuration(t,
		time.Now(), crt.Certificate().NotBefore, time.Second*5,
		"Certificate should be valid from about now",
	)
	require.Equal(t,
		time.Minute, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should be have default TTL",
	)
	require.Equal(t,
		"trustme-go: certificate #1000", crt.Certificate().Subject.CommonName,
		"Certificate should have default CN",
	)
	require.Equal(t,
		"trustme-go Org.", crt.Certificate().Subject.Organization[0],
		"Certificate should have default O",
	)
	require.Equal(t, 2048/8, crt.Key().Size(), "Key should have default size")
}

func TestCA_Issue_DefaultTTL_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t, trustme.WithTTL(time.Minute*123))

	// When
	crt := fca.MustIssue()

	// Then
	require.Equal(t,
		time.Minute*123, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func TestCA_Issue_DefaultRSaBits_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t, trustme.WithRSABits(1024))

	// When
	crt := fca.MustIssue()

	// Then
	require.Equal(t, 1024/8, crt.Key().Size(), "Key should have size set via options")
}

func TestCA_Issue_DefaultCommonName_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t, trustme.WithCommonName("test-CN"))

	// When
	crt := fca.MustIssue()

	// Then
	require.Regexp(t,
		"^test-CN:", crt.Certificate().Subject.CommonName,
		"Certificate should have CN set via options",
	)
}

func TestCA_Issue_DefaultOrganization_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t, trustme.WithOrganization("Trust Me, Org."))

	// When
	crt := fca.MustIssue()

	// Then
	require.Equal(t,
		"Trust Me, Org.", crt.Certificate().Subject.Organization[0],
		"Certificate should have O set via options",
	)
}

func TestCA_Issue_MultipleDefaultOptions_Effective(t *testing.T) {
	// Given
	fca := trustme.New(
		t,
		trustme.WithRSABits(1024),
		trustme.WithTTL(time.Minute*123),
	)

	// When
	crt := fca.MustIssue()

	// Then
	require.Equal(t, 1024/8, crt.Key().Size(), "Key should have size set via options")
	require.Equal(t,
		time.Minute*123, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func TestCA_Issue_WithTTL_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t)

	// When
	crt := fca.MustIssue(trustme.WithTTL(time.Hour * 123))

	// Then
	require.Equal(t,
		time.Hour*123, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should have TTL set via options",
	)
}

func TestCA_Issue_WithRSABits_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t)

	// When
	crt := fca.MustIssue(trustme.WithRSABits(1024))

	// Then
	require.Equal(t, 1024/8, crt.Key().Size(), "Key should have size set via options")
}

func TestCA_Issue_WithCommonName_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t)

	// When
	crt := fca.MustIssue(trustme.WithCommonName("cert-test-CN"))

	// Then
	require.Equal(t,
		"cert-test-CN", crt.Certificate().Subject.CommonName,
		"Certificate should have CN set via options",
	)
}

func TestCA_Issue_MultipleOptions_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t)

	// When
	crt := fca.MustIssue(
		trustme.WithRSABits(1024),
		trustme.WithTTL(time.Minute*123),
	)

	// Then
	require.Equal(t, 1024/8, crt.Key().Size(), "Key should have size set via options")
	require.Equal(t,
		time.Minute*123, crt.Certificate().NotAfter.Sub(crt.Certificate().NotBefore),
		"Certificate should have TTL set via CA options",
	)
}

func TestCA_Issue_WithDNS_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t)

	// When
	crt := fca.MustIssue(
		trustme.WithDNS("dns.a"),
		trustme.WithDNS("dns.b"),
	)

	// Then
	require.ElementsMatch(t,
		crt.Certificate().DNSNames, []string{"dns.a", "dns.b"},
		"Certificate should have DNS names SAN set via options",
	)
}

func TestCA_Issue_WithIP_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t)

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
	require.ElementsMatch(t,
		certIPs, []string{"8.8.8.8", "127.0.0.1", "::1"},
		"Certificate should have IP addresses names SAN set via options",
	)
}

func TestCA_Issue_WithEmail_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t)

	// When
	crt := fca.MustIssue(
		trustme.WithEmail("example@example.com"),
		trustme.WithEmail("test@example.com"),
	)

	// Then
	require.ElementsMatch(t,
		crt.Certificate().EmailAddresses, []string{"example@example.com", "test@example.com"},
		"Certificate should have email addresses names SAN set via options",
	)
}

func TestCA_Issue_WithURI_Effective(t *testing.T) {
	// Given
	fca := trustme.New(t)

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
	require.ElementsMatch(t,
		crt.Certificate().URIs, []*url.URL{uri1, uri2},
		"Certificate should have email addresses names SAN set via options",
	)
}

func TestCA_Issue_SerialNumberChanges(t *testing.T) {
	// Given
	fca := trustme.New(t)

	// When
	crt1 := fca.MustIssue()
	crt2 := fca.MustIssue()

	// Then
	require.Equal(t, big.NewInt(1000), crt1.Certificate().SerialNumber)
	require.Equal(t, big.NewInt(1001), crt2.Certificate().SerialNumber)
}
