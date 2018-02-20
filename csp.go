package csp

import (
	"fmt"
	"net/http"
	"strings"
)

// CSP header keys
const (
	HeaderPolicy     = "Content-Security-Policy"
	HeaderReport     = "Content-Security-Policy-Report"
	HeaderReportOnly = "Content-Security-Policy-Report-Only"

	ReportContentType = "application/csp-report"
)

// CSP standard source types
const (
	SourceNone = "'none'"
	SourceSelf = "'self'"
	SourceAny  = "*"
)

// Fetch directives
// https://www.w3.org/TR/CSP/#directives-fetch
const (
	childSrc    = "child-src"
	connectSrc  = "connect-src"
	defaultSrc  = "default-src"
	fontSrc     = "font-src"
	frameSrc    = "frame-src"
	imgSrc      = "img-src"
	manifestSrc = "manifest-src"
	mediaSrc    = "media-src"
	objectSrc   = "object-src"
	scriptSrc   = "script-src"
	styleSrc    = "style-src"
	workerSrc   = "worker-src"

	// Reporting
	reportTo = "report-to"
)

// CSP Configuration Structure
type CSP struct {
	ReportOnly bool // ReportOnly sets CSP into report only mode

	// Fetch directives
	ChildSrc    SourceList
	ConnectSrc  SourceList
	DefaultSrc  SourceList
	FontSrc     SourceList
	FrameSrc    SourceList
	ImgSrc      SourceList
	ManifestSrc SourceList
	MediaSrc    SourceList
	ObjectSrc   SourceList
	ScriptSrc   SourceList
	StyleSrc    SourceList
	WorkerSrc   SourceList

	// Reporting
	ReportTo string

	h http.Handler
}

// Report CSP report structure
type Report struct {
	DocumentURI       string `json:"document-uri"`
	Referrer          string `json:"referrer"`
	BlockedURI        string `json:"blocked-uri"`
	ViolatedDirective string `json:"violated-directive"`
	OriginalPolicy    string `json:"original-policy"`
	Disposition       string `json:"disposition"`
}

// Default generates a default / basic CSP policy with
// a default of 'none' and 'default-src', 'script-src', 'connect-src', 'img-src' and 'style-src' set to 'self'.
func Default() CSP {
	return CSP{
		DefaultSrc: NewSourceList(SourceNone),
		ScriptSrc:  NewSourceList(SourceSelf),
		ConnectSrc: NewSourceList(SourceSelf),
		ImgSrc:     NewSourceList(SourceSelf),
		StyleSrc:   NewSourceList(SourceSelf),
	}
}

// ServeHTTP is an http.Handler instance that attaches CSP headers to all requests
func (c *CSP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := HeaderPolicy
	if c.ReportOnly {
		key = HeaderReportOnly
	}

	val, err := c.MarshalText()
	if err != nil {
		return
	}

	w.Header().Set(key, string(val))

	c.h.ServeHTTP(w, r)
}

// Handler wraps an http.Handler in a CSP instance
func (c *CSP) Handler(h http.Handler) http.Handler {
	c.h = h
	return c
}

// MarshalText marshals a CSP policy to text
func (c *CSP) MarshalText() ([]byte, error) {
	policies := make([]string, 0)

	if len(c.DefaultSrc) != 0 {
		txt, _ := c.DefaultSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", defaultSrc, txt))
	}
	if len(c.ChildSrc) != 0 {
		txt, _ := c.ChildSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", childSrc, txt))
	}
	if len(c.ConnectSrc) != 0 {
		txt, _ := c.ConnectSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", connectSrc, txt))
	}
	if len(c.FontSrc) != 0 {
		txt, _ := c.FontSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", fontSrc, txt))
	}
	if len(c.FrameSrc) != 0 {
		txt, _ := c.FrameSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", frameSrc, txt))
	}
	if len(c.ImgSrc) != 0 {
		txt, _ := c.ImgSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", imgSrc, txt))
	}
	if len(c.ManifestSrc) != 0 {
		txt, _ := c.ManifestSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", manifestSrc, txt))
	}
	if len(c.MediaSrc) != 0 {
		txt, _ := c.MediaSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", mediaSrc, txt))
	}
	if len(c.ObjectSrc) != 0 {
		txt, _ := c.ObjectSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", objectSrc, txt))
	}
	if len(c.ScriptSrc) != 0 {
		txt, _ := c.ScriptSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", scriptSrc, txt))
	}
	if len(c.StyleSrc) != 0 {
		txt, _ := c.StyleSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", styleSrc, txt))
	}
	if len(c.WorkerSrc) != 0 {
		txt, _ := c.WorkerSrc.MarshalText()
		policies = append(policies, fmt.Sprintf("%s %s", workerSrc, txt))
	}

	if c.ReportTo != "" {
		policies = append(policies, fmt.Sprintf("%s %s", reportTo, c.ReportTo))
	}

	return []byte(strings.TrimSpace(strings.Join(policies, "; "))), nil
}

// UnmarshalText un-marshals a CSP policy from text
func (c *CSP) UnmarshalText(text []byte) error {
	policies := strings.Split(string(text), ";")

	// Read polices into a map
	for _, p := range policies {
		l := strings.SplitN(strings.TrimSpace(p), " ", 2)
		if p == "" || len(l) != 2 {
			continue
		}
		k, v := strings.TrimSpace(l[0]), strings.TrimSpace(l[1])

		switch k {
		case childSrc:
			c.ChildSrc.UnmarshalText([]byte(v))
		case connectSrc:
			c.ConnectSrc.UnmarshalText([]byte(v))
		case defaultSrc:
			c.DefaultSrc.UnmarshalText([]byte(v))
		case fontSrc:
			c.FontSrc.UnmarshalText([]byte(v))
		case frameSrc:
			c.FrameSrc.UnmarshalText([]byte(v))
		case imgSrc:
			c.ImgSrc.UnmarshalText([]byte(v))
		case manifestSrc:
			c.ManifestSrc.UnmarshalText([]byte(v))
		case mediaSrc:
			c.MediaSrc.UnmarshalText([]byte(v))
		case objectSrc:
			c.ObjectSrc.UnmarshalText([]byte(v))
		case scriptSrc:
			c.ScriptSrc.UnmarshalText([]byte(v))
		case styleSrc:
			c.StyleSrc.UnmarshalText([]byte(v))
		case workerSrc:
			c.WorkerSrc.UnmarshalText([]byte(v))
		case reportTo:
			c.ReportTo = v
		}
	}

	return nil
}

// SourceList List of CSP sources
type SourceList []string

// NewSourceList creates a source list from a varadic list of sources
func NewSourceList(sources ...string) SourceList {
	s := make(SourceList, len(sources))
	for i, v := range sources {
		s[i] = v
	}
	return s
}

// MarshalText marshals a source list to text
func (s SourceList) MarshalText() ([]byte, error) {
	str := strings.Join(s, " ")
	return []byte(str), nil
}

// UnmarshalText unmarshals a source list from text
func (s *SourceList) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}
