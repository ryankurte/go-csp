package csp

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cspString = "default-src 'none'; connect-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'"
const reportString = ` {
	"csp-report": {
	  "document-uri": "http://example.com/signup.html",
	  "referrer": "",
	  "blocked-uri": "http://example.com/css/style.css",
	  "violated-directive": "style-src cdn.example.com",
	  "original-policy": "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports",
	  "disposition": "report"
	}
}`

type MockReporter struct {
	r Report
}

func (mr *MockReporter) Report(r Report) error {
	mr.r = r
	return nil
}
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

	// Mozilla examples from https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
	marshalTests := []struct {
		name string
		csp  CSP
		txt  string
	}{
		{"Default CSP", Default(), cspString},
		{"Mozilla example 1",
			CSP{
				DefaultSrc: NewSourceList(SourceSelf),
			},
			"default-src 'self'",
		}, {"Mozilla example 2",
			CSP{
				DefaultSrc: NewSourceList(SourceSelf, "*.trusted.com"),
			},
			"default-src 'self' *.trusted.com",
		}, {"Mozilla example 3",
			CSP{
				DefaultSrc: NewSourceList(SourceSelf),
				ImgSrc:     NewSourceList(SourceAny),
				MediaSrc:   NewSourceList("media1.com", "media2.com"),
				ScriptSrc:  NewSourceList("userscripts.example.com"),
			},
			"default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com",
		}, {"Mozilla example 4",
			CSP{
				DefaultSrc: NewSourceList("https://onlinebanking.jumbobank.com"),
			},
			"default-src https://onlinebanking.jumbobank.com",
		}, {"Mozilla example 5",
			CSP{
				DefaultSrc: NewSourceList(SourceSelf, "*.mailsite.com"),
				ImgSrc:     NewSourceList(SourceAny),
			},
			"default-src 'self' *.mailsite.com; img-src *",
		},
	}

	for _, v := range marshalTests {
		t.Run(fmt.Sprintf("Marshal Unmarshal %s", v.name), func(t *testing.T) {
			txt, err := v.csp.MarshalText()
			require.Nil(t, err)
			assert.EqualValues(t, v.txt, string(txt))

			csp2 := CSP{}
			err = csp2.UnmarshalText(txt)
			require.Nil(t, err)
			assert.EqualValues(t, v.csp, csp2)
		})
	}

	t.Run("Unmarshal reports", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(reportString)))
		req.Header.Set("Content-Type", ReportContentType)
		rw := httptest.NewRecorder()

		mr := MockReporter{}
		h := RouteHandler(&mr)

		rep := Report{
			DocumentURI:       "http://example.com/signup.html",
			BlockedURI:        "http://example.com/css/style.css",
			ViolatedDirective: "style-src cdn.example.com",
			OriginalPolicy:    "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports",
			Disposition:       "report",
		}

		h(rw, req)
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, rep, mr.r)
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
