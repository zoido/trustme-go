package trustme

import "github.com/zoido/trustme-go/ca"

// NewCA returns new instance of th CA.
func NewCA(options ...ca.Option) (*ca.CA, error) {
	return ca.New(options...)
}
