package trustme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// Authority is a fake certification authority for issuing TLS certificates for tests.
// It provides the "errorless" interface where the test fails when the operation would return error.
type Authority struct {
	t *testing.T

	keyPair *KeyPair

	cfg       *authorityConfig
	serial    *big.Int
	serialInc *big.Int
}

// New returns new instance of th CA and fails the test when creation fails.
func New(t *testing.T, options ...AuthorityOption) *Authority {
	cfg := &authorityConfig{
		rsaBits:      2048,
		ttl:          time.Minute,
		commonName:   "trustme-go",
		organization: "trustme-go Org.",
	}

	for _, opt := range options {
		opt.applyAuthority(cfg)
	}

	a := &Authority{
		t: t,

		keyPair: &KeyPair{},
		cfg:     cfg,

		serial:    big.NewInt(1000),
		serialInc: big.NewInt(1),
	}

	err := a.initialize()

	if err != nil {
		t.Error(err)
	}

	return a
}

// Certificate returns public certificate of underlying fake CA.
func (a *Authority) Certificate() *x509.Certificate {
	return a.keyPair.certificate
}

// Key returns private key of underlying fake CA.
func (a *Authority) Key() *rsa.PrivateKey {
	return a.keyPair.privateKey
}

// MustIssue issues new certificate signed by the CA. Fails the test
func (a *Authority) MustIssue(options ...IssueOption) *KeyPair {
	cfg := issueConfig{
		rsaBits: a.cfg.rsaBits,
		ttl:     a.cfg.ttl,

		commonName:   fmt.Sprintf("%s: certificate #%d", a.cfg.commonName, a.serial),
		organization: a.cfg.organization,
	}
	for _, opt := range options {
		opt.applyIssue(&cfg)
	}

	pair, err := a.issueCertificate(cfg)
	a.checkError(err)
	if err == nil {
		a.serial.Add(a.serial, a.serialInc)
	}

	return pair
}

func (a *Authority) issueCertificate(cfg issueConfig) (*KeyPair, error) {
	var err error
	pair := &KeyPair{t: a.t}

	pair.privateKey, err = generateKey(cfg.rsaBits)
	if err != nil {
		return nil, fmt.Errorf("generating the private key: %w", err)
	}

	csr, err := generateCSR(cfg, pair.privateKey)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		Subject:      csr.Subject,
		SerialNumber: a.serial,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(cfg.ttl),

		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		Issuer: a.keyPair.certificate.Issuer,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,

		DNSNames:       cfg.dnsNames,
		IPAddresses:    cfg.ipAddresses,
		EmailAddresses: cfg.emailAddresses,
		URIs:           cfg.uris,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, a.keyPair.certificate,
		csr.PublicKey, a.keyPair.privateKey)
	if err != nil {
		return nil, fmt.Errorf("generating CA certificate: %w", err)
	}

	pair.certificate, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CA certificate: %w", err)
	}

	return pair, nil
}

func (a *Authority) initialize() error {
	var err error

	a.keyPair.privateKey, err = generateKey(a.cfg.rsaBits)
	if err != nil {
		return fmt.Errorf("generating CA private key: %w", err)
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   a.cfg.commonName,
			Organization: []string{a.cfg.organization},
		},
		SerialNumber: big.NewInt(1),

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(a.cfg.ttl),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&a.keyPair.privateKey.PublicKey, a.keyPair.privateKey)
	if err != nil {
		return fmt.Errorf("generating CA certificate: %w", err)
	}

	a.keyPair.certificate, err = x509.ParseCertificate(certificateBytes)
	if err != nil {
		return fmt.Errorf("parsing generated CA certificate: %w", err)
	}
	return nil
}

func generateKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func generateCSR(cfg issueConfig, key *rsa.PrivateKey) (*x509.CertificateRequest, error) {
	subject := pkix.Name{
		CommonName:   cfg.commonName,
		Organization: []string{cfg.organization},
	}
	asn1Subject, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed ASN1 CSR subject: %w", err)
	}

	csrTemplate := x509.CertificateRequest{
		RawSubject:         asn1Subject,
		SignatureAlgorithm: x509.SHA512WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("generating CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CSR: %w", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("checking CSR Signature: %w", err)
	}

	return csr, nil
}

func (a *Authority) checkError(err error) {
	if err != nil {
		a.t.Error(err)
	}
}
