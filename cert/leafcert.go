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

// Config holds the configration of the issueing of the cingle certificate.
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
