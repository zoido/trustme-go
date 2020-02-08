package ca_test

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/zoido/trustme-go/ca"
)

type CATestSuite struct {
	suite.Suite
}

func TestCATestSuite(t *testing.T) {
	suite.Run(t, new(CATestSuite))
}

func (s *CATestSuite) TestCA_Ok() {
	// When
	_, err := ca.New()

	// Then
	s.Require().NoError(err)
}

func (s *CATestSuite) TestCA_Issue_Ok() {
	// Given
	a := s.mustCreateCA()

	// When
	_, err := a.Issue()

	// Then
	s.Require().NoError(err)
}

func (s *CATestSuite) mustCreateCA(opts ...ca.Option) *ca.CA {
	a, err := ca.New(opts...)
	s.Require().NoError(err, "creating CA under test")
	return a
}
