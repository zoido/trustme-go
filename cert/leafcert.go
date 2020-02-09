package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"time"
)

// LeafCert represents server or client certificate
type LeafCert struct {
	Certificate      *x509.Certificate
	CertificateBytes []byte

	Key      *rsa.PrivateKey
	KeyBytes []byte
}

// Config holds the configration of the issuing of the single certificate.
type Config struct {
	TTL     time.Duration
	RSABits int

	CommonName   string
	Organization string
}

// Option configures the issued certificate.
type Option func(cfg *Config)

// WithOptions turns a list of LeafOption instances into an LeafOption.
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
