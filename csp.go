package csp

import (
	"encoding"
	"fmt"
	"reflect"
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

const cspTag = "csp"

// CSP Directive Structure
// https://www.w3.org/TR/CSP/#directives-fetch
type CSP struct {
	// Fetch directives
	ChildSrc    SourceList `csp:"child-src"`
	ConnectSrc  SourceList `csp:"connect-src"`
	DefaultSrc  SourceList `csp:"default-src"`
	FontSrc     SourceList `csp:"font-src"`
	FrameSrc    SourceList `csp:"frame-src"`
	ImgSrc      SourceList `csp:"img-src"`
	ManifestSrc SourceList `csp:"manifest-src"`
	MediaSrc    SourceList `csp:"media-src"`
	ObjectSrc   SourceList `csp:"object-src"`
	ScriptSrc   SourceList `csp:"script-src"`
	StyleSrc    SourceList `csp:"style-src"`
	WorkerSrc   SourceList `csp:"worker-src"`

	// Reporting
	ReportTo string `csp:"report-to"`
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

// MarshalText marshals a CSP policy to text
func (c *CSP) MarshalText() ([]byte, error) {
	policy := HeaderPolicy

	v := reflect.ValueOf(*c)
	t := reflect.TypeOf(*c)
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		val := v.Field(i)
		tag := field.Tag.Get(cspTag)

		if val.Type() == reflect.ValueOf(SourceList{}).Type() {
			if val.Len() == 0 {
				continue
			}
			marshaler, ok := val.Interface().(encoding.TextMarshaler)
			if !ok {
				return nil, fmt.Errorf("field %s does not implement encoding.TextMarshaler", field.Name)
			}
			v, err := marshaler.MarshalText()
			if err != nil {
				return nil, err
			}

			policy += fmt.Sprintf(" %s %s;", tag, string(v))
		} else if val.Type() == reflect.ValueOf("").Type() {
			if val.String() == "" {
				continue
			}
			policy += fmt.Sprintf(" %s %s;", tag, val.String())
		}
	}

	return []byte(policy), nil
}

// UnmarshalText un-marshals a CSP policy from text
func (c *CSP) UnmarshalText(text []byte) error {
	policies := strings.Split(string(text), ";")

	// Read polices into a map
	policyMap := make(map[string]string)
	for _, p := range policies {
		l := strings.SplitN(strings.TrimSpace(p), " ", 2)
		if len(l) != 2 {
			continue
		}
		policyMap[l[0]] = l[1]
	}

	// Reflect map values onto struct
	v := reflect.ValueOf(c)
	t := reflect.TypeOf(*c)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		val := v.Elem().Field(i)

		tag := field.Tag.Get(cspTag)
		if tag == "" {
			continue
		}
		sources, ok := policyMap[tag]
		if !ok {
			continue
		}

		if field.Type == reflect.ValueOf(SourceList{}).Type() {
			sl := SourceList{}
			err := sl.UnmarshalText([]byte(sources))
			if err != nil {
				return err
			}
			fmt.Printf("Field: %s sources: '%s' sl: %+v\n", field.Name, sources, sl)
			val.Set(reflect.ValueOf(sl))
		} else if field.Type == reflect.ValueOf("").Type() {
			val.SetString(sources)
		}
	}

	v.Elem().Set(reflect.ValueOf(*c))

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
