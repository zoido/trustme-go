package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"net"
	"net/url"
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

	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

// Option configures the issued certificate.
type Option func(cfg *Config)

// WithOptions turns a list of Option instances into an Option.
func WithOptions(opts ...Option) Option {
	return func(cfg *Config) {
		for _, opt := range opts {
			opt(cfg)
		}
	}
}

// WithTTL configures time to live of the issued certificate.
func WithTTL(ttl time.Duration) Option {
	return func(cfg *Config) {
		cfg.TTL = ttl
	}
}

// WithRSABits configures the length of RSA private key issued certificate.
func WithRSABits(rsaBits int) Option {
	return func(cfg *Config) {
		cfg.RSABits = rsaBits
	}
}

// WithCommonName configures common name of the issued certificate.
func WithCommonName(commonName string) Option {
	return func(cfg *Config) {
		cfg.CommonName = commonName
	}
}

// WithDNS configures DNS names SANs of the issued certificate. Can be used multiple times.
func WithDNS(name string) Option {
	return func(cfg *Config) {
		cfg.DNSNames = append(cfg.DNSNames, name)
	}
}

// WithIP configures DNS names SANs of the issued certificate. Can be used multiple times.
func WithIP(ipAddress net.IP) Option {
	return func(cfg *Config) {
		cfg.IPAddresses = append(cfg.IPAddresses, ipAddress)
	}
}

// WithEmail configures e-mail adresses SANs of the issued certificate. Can be used multiple times.
func WithEmail(email string) Option {
	return func(cfg *Config) {
		cfg.EmailAddresses = append(cfg.EmailAddresses, email)
	}
}

// WithURI configures URIs SANs of the issued certificate. Can be used multiple times.
func WithURI(uri *url.URL) Option {
	return func(cfg *Config) {
		cfg.URIs = append(cfg.URIs, uri)
	}
}
