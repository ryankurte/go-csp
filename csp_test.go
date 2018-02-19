package csp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testf struct {
	name string
	csp  CSP
	val  string
}

func TestCSP(t *testing.T) {
	defaultCSP := "connect-src 'self'; default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self';"

	t.Run("Marshal CSP", func(t *testing.T) {
		csp := Default()
		v, err := csp.MarshalText()
		require.Nil(t, err)
		assert.EqualValues(t, defaultCSP, string(v))
	})

	t.Run("Unmarshal CSP", func(t *testing.T) {
		csp := CSP{}
		err := csp.UnmarshalText([]byte(defaultCSP))
		require.Nil(t, err)
		assert.EqualValues(t, Default(), csp)
	})
}
