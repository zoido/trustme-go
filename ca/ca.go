package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/zoido/trustme-go/cert"
)

// CA is a fake certification authority for issuing TLS certificates for tests.
type CA struct {
	Certificate      *x509.Certificate
	CertificateBytes []byte
	Key              *rsa.PrivateKey

	cfg Config

	serial int64
}

// Option configures the CA.
type Option func(fca *Config)

// Config holds the configration of the CA.
type Config struct {
	TTL     time.Duration
	RSABits int

	CommonName   string
	Organization string
}

// New returns new instance of th CA.
func New(options ...Option) (*CA, error) {
	cfg := &Config{}
	for _, opt := range options {
		opt(cfg)
	}

	ca := &CA{
		serial: 1,
		cfg:    *cfg,
	}

	err := ca.initialize()
	if err != nil {
		return nil, fmt.Errorf("failed initializing the CA: %w", err)
	}
	return ca, nil
}

// WithCAOptions turns a list of CAOption instances into an CAOption.
func WithCAOptions(opts ...Option) Option {
	return func(cfg *Config) {
		for _, opt := range opts {
			opt(cfg)
		}
	}
}

// WithTTL configures time to live for the CA and issued certificates.
func WithTTL(ttl time.Duration) Option {
	return func(cfg *Config) {
		cfg.TTL = ttl
	}
}

// WithRSABits configures the length of RSA private key of the CA and the issued certificates.
func WithRSABits(rsaBits int) Option {
	return func(cfg *Config) {
		cfg.RSABits = rsaBits
	}
}

// WithCommonName configures the CA's common name.
func WithCommonName(commonName string) Option {
	return func(cfg *Config) {
		cfg.CommonName = commonName
	}
}

// WithOrganization configures the CA's organization.
func WithOrganization(organization string) Option {
	return func(cfg *Config) {
		cfg.Organization = organization
	}
}

// Issue issues new certificate signed by the CA.
func (fca *CA) Issue(options ...cert.Option) (*cert.LeafCert, error) {
	cfg := cert.Config{
		RSABits: fca.cfg.RSABits,
		TTL:     fca.cfg.TTL,

		CommonName:   fmt.Sprintf("%s: certificate #%d", fca.cfg.CommonName, fca.serial),
		Organization: fca.cfg.Organization,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	return fca.issueCertificate(cfg)
}

func (fca *CA) issueCertificate(cfg cert.Config) (*cert.LeafCert, error) {
	var err error
	leaf := &cert.LeafCert{}

	leaf.Key, err = generateKey(cfg.RSABits)
	if err != nil {
		return nil, fmt.Errorf("generating the private key: %w", err)
	}

	csr, err := generateCSR(cfg, *leaf.Key)

	template := x509.Certificate{
		Subject: csr.Subject,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(cfg.TTL),

		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		Issuer: fca.Certificate.Issuer,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	leaf.CertificateBytes, err = x509.CreateCertificate(rand.Reader, &template, fca.Certificate,
		csr.PublicKey, fca.Key)
	if err != nil {
		return nil, fmt.Errorf("generating CA certificate: %w", err)
	}

	leaf.Certificate, err = x509.ParseCertificate(leaf.CertificateBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CA certificate: %w", err)
	}

	return leaf, nil
}

func (fca *CA) initialize() error {
	var err error

	fca.Key, err = generateKey(fca.cfg.RSABits)
	if err != nil {
		return fmt.Errorf("generating CA private key: %w", err)
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   fca.cfg.CommonName,
			Organization: []string{fca.cfg.Organization},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(fca.cfg.TTL),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	fca.CertificateBytes, err = x509.CreateCertificate(rand.Reader, &template, &template,
		&fca.Key.PublicKey, fca.Key)
	if err != nil {
		return fmt.Errorf("generating CA certificate: %w", err)
	}

	fca.Certificate, err = x509.ParseCertificate(fca.CertificateBytes)
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

func generateCSR(cfg cert.Config, key rsa.PrivateKey) (*x509.CertificateRequest, error) {
	subject := pkix.Name{
		CommonName:   cfg.CommonName,
		Organization: []string{cfg.Organization},
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
