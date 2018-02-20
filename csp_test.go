package csp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cspString = "default-src 'none'; connect-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'"

func TestCSP(t *testing.T) {

	t.Run("Marshal CSP", func(t *testing.T) {
		csp := Default()
		v, err := csp.MarshalText()
		require.Nil(t, err)
		assert.EqualValues(t, cspString, string(v))
	})

	t.Run("Unmarshal CSP", func(t *testing.T) {
		csp := CSP{}
		err := csp.UnmarshalText([]byte(cspString))
		require.Nil(t, err)
		assert.EqualValues(t, Default(), csp)
	})
}

func BenchmarkCSP(b *testing.B) {
	b.Run("Marshal CSP", func(b *testing.B) {
		csp := Default()
		for i := 0; i < b.N; i++ {
			csp.MarshalText()
		}
	})

	b.Run("Unmarshal CSP", func(b *testing.B) {
		csp := CSP{}
		for i := 0; i < b.N; i++ {
			csp.UnmarshalText([]byte(cspString))
		}
	})
}
