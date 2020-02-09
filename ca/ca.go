package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/zoido/trustme-go/cert"
)

// CA is a fake certification authority for issuing TLS certificates for tests.
type CA struct {
	Cert *cert.LeafCert

	cfg       *Config
	serial    *big.Int
	serialInc *big.Int
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
	cfg := &Config{
		RSABits:      2048,
		TTL:          time.Minute,
		CommonName:   "trustme-go",
		Organization: "trustme-go Org.",
	}
	for _, opt := range options {
		opt(cfg)
	}

	ca := &CA{
		Cert: &cert.LeafCert{},
		cfg:  cfg,

		serial:    big.NewInt(1000),
		serialInc: big.NewInt(1),
	}

	err := ca.initialize()
	if err != nil {
		return nil, fmt.Errorf("failed initializing the CA: %w", err)
	}
	return ca, nil
}

// WithOptions turns a list of CAOption instances into an CAOption.
func WithOptions(opts ...Option) Option {
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
func (ca *CA) Issue(options ...cert.Option) (*cert.LeafCert, error) {
	cfg := cert.Config{
		RSABits: ca.cfg.RSABits,
		TTL:     ca.cfg.TTL,

		CommonName:   fmt.Sprintf("%s: certificate #%d", ca.cfg.CommonName, ca.serial),
		Organization: ca.cfg.Organization,
	}
	for _, opt := range options {
		opt(&cfg)
	}

	leaf, err := ca.issueCertificate(cfg)
	if err == nil {
		ca.serial.Add(ca.serial, ca.serialInc)
	}

	return leaf, err
}

func (ca *CA) issueCertificate(cfg cert.Config) (*cert.LeafCert, error) {
	var err error
	leaf := &cert.LeafCert{}

	leaf.Key, err = generateKey(cfg.RSABits)
	if err != nil {
		return nil, fmt.Errorf("generating the private key: %w", err)
	}

	csr, err := generateCSR(cfg, leaf.Key)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		Subject:      csr.Subject,
		SerialNumber: ca.serial,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(cfg.TTL),

		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		Issuer: ca.Cert.Certificate.Issuer,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,

		DNSNames:       cfg.DNSNames,
		IPAddresses:    cfg.IPAddresses,
		EmailAddresses: cfg.EmailAddresses,
		URIs:           cfg.URIs,
	}

	leaf.CertificateBytes, err = x509.CreateCertificate(rand.Reader, &template, ca.Cert.Certificate,
		csr.PublicKey, ca.Cert.Key)
	if err != nil {
		return nil, fmt.Errorf("generating CA certificate: %w", err)
	}

	leaf.Certificate, err = x509.ParseCertificate(leaf.CertificateBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CA certificate: %w", err)
	}

	return leaf, nil
}

func (ca *CA) initialize() error {
	var err error

	ca.Cert.Key, err = generateKey(ca.cfg.RSABits)
	if err != nil {
		return fmt.Errorf("generating CA private key: %w", err)
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   ca.cfg.CommonName,
			Organization: []string{ca.cfg.Organization},
		},
		SerialNumber: big.NewInt(1),

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(ca.cfg.TTL),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&ca.Cert.Key.PublicKey, ca.Cert.Key)
	if err != nil {
		return fmt.Errorf("generating CA certificate: %w", err)
	}

	ca.Cert.Certificate, err = x509.ParseCertificate(certificateBytes)
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

func generateCSR(cfg cert.Config, key *rsa.PrivateKey) (*x509.CertificateRequest, error) {
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
