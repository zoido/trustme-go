package trustme

import (
	"net"
	"net/url"
	"time"
)

// AuthorityOption configures the Authority.
type AuthorityOption interface {
	applyAuthority(cfg *authorityConfig)
}

// IssueOption configures the issued KeyPair.
type IssueOption interface {
	applyIssue(cfg *issueConfig)
}

// Option configures the Authority and the issued KeyPair.
type Option interface {
	AuthorityOption
	IssueOption
}

type authorityConfig struct {
	ttl     time.Duration
	rsaBits int

	commonName   string
	organization string
}

type issueConfig struct {
	ttl     time.Duration
	rsaBits int

	commonName   string
	organization string

	dnsNames       []string
	emailAddresses []string
	ipAddresses    []net.IP
	uris           []*url.URL
}

// WithTTL configures time to live of the CA's and issued certificates.
func WithTTL(ttl time.Duration) Option {
	return withTTL{ttl}
}

type withTTL struct {
	ttl time.Duration
}

func (o withTTL) applyAuthority(cfg *authorityConfig) {
	cfg.ttl = o.ttl
}

func (o withTTL) applyIssue(cfg *issueConfig) {
	cfg.ttl = o.ttl
}

// WithRSABits configures the length of RSA private key of the CA's and issued certificate.
func WithRSABits(rsaBits int) Option {
	return withRSABits{rsaBits}
}

type withRSABits struct {
	rsaBits int
}

func (o withRSABits) applyAuthority(cfg *authorityConfig) {
	cfg.rsaBits = o.rsaBits
}

func (o withRSABits) applyIssue(cfg *issueConfig) {
	cfg.rsaBits = o.rsaBits
}

// WithCommonName configures common name of the issued certificate.
func WithCommonName(commonName string) Option {
	return withCommonName{commonName}
}

type withCommonName struct {
	commonName string
}

func (o withCommonName) applyAuthority(cfg *authorityConfig) {
	cfg.commonName = o.commonName
}

func (o withCommonName) applyIssue(cfg *issueConfig) {
	cfg.commonName = o.commonName
}

// WithOrganization configures the CA's organization.
func WithOrganization(organization string) AuthorityOption {
	return withOrganization{organization}
}

type withOrganization struct {
	organization string
}

func (o withOrganization) applyAuthority(cfg *authorityConfig) {
	cfg.organization = o.organization
}

// WithDNS configures DNS names SANs of the issued certificate. Can be used multiple times.
func WithDNS(name string) IssueOption {
	return withDNS{name}
}

type withDNS struct {
	name string
}

func (o withDNS) applyIssue(cfg *issueConfig) {
	cfg.dnsNames = append(cfg.dnsNames, o.name)
}

// WithIP configures DNS names SANs of the issued certificate. Can be used multiple times.
func WithIP(ipAddress net.IP) IssueOption {
	return withIP{ipAddress}
}

type withIP struct {
	ipAddress net.IP
}

func (o withIP) applyIssue(cfg *issueConfig) {
	cfg.ipAddresses = append(cfg.ipAddresses, o.ipAddress)
}

// WithEmail configures e-mail adresses SANs of the issued certificate. Can be used multiple times.
func WithEmail(email string) IssueOption {
	return withEmail{email}
}

type withEmail struct {
	emailAddresses string
}

func (o withEmail) applyIssue(cfg *issueConfig) {
	cfg.emailAddresses = append(cfg.emailAddresses, o.emailAddresses)
}

// WithURI configures URIs SANs of the issued certificate. Can be used multiple times.
func WithURI(uri *url.URL) IssueOption {
	return withURI{uri}
}

type withURI struct {
	uri *url.URL
}

func (o withURI) applyIssue(cfg *issueConfig) {
	cfg.uris = append(cfg.uris, o.uri)
}
