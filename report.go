package csp

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// CSP header keys
const (
	HeaderPolicy     = "Content-Security-Policy"
	HeaderReport     = "Content-Security-Policy-Report"
	HeaderReportOnly = "Content-Security-Policy-Report-Only"

	ReportContentType = "application/csp-report"
)

// Report CSP report structure
type Report struct {
	DocumentURI        string `json:"document-uri"`
	Referrer           string `json:"referrer"`
	BlockedURI         string `json:"blocked-uri"`
	EffectiveDirective string `json:"effective-directive"`
	ViolatedDirective  string `json:"violated-directive"`
	OriginalPolicy     string `json:"original-policy"`
	Disposition        string `json:"disposition"`
	StatusCode         int    `json:"status"`
}

type cspReport struct {
	Report `json:"csp-report"`
}

// ReportHandler is an interface that handles receiving CSP reports
type ReportHandler interface {
	Report(r Report) error
}

type defaultLogReporter struct{}

// LogReporter is a ReportHandler that logs CSP reports
func (l *defaultLogReporter) Report(r Report) error {
	log.Printf("CSP report: %v", r)
	return nil
}

// ErrorHandler is a function that handles errors in the CSR report handler endpoint
type ErrorHandler interface {
	Error(w http.ResponseWriter, r *http.Request, status int, err error)
}

type defaultErrorHandler struct{}

// DefaultErrorHandler logs and returns errors to requester
func (e *defaultErrorHandler) Error(w http.ResponseWriter, r *http.Request, status int, err error) {
	log.Println(err)
	w.Write([]byte(err.Error()))
	w.WriteHeader(status)
}

// Handler creates a CSR Report handler for binding to a route
// This accepts and ErrorHandler and/or ReportHandler argument(s) to override default error and report handers
func RouteHandler(opts ...interface{}) http.HandlerFunc {
	var reportHandler ReportHandler = &defaultLogReporter{}
	var errorHandler ErrorHandler = &defaultErrorHandler{}
	for _, opt := range opts {
		if r, ok := opt.(ReportHandler); ok {
			reportHandler = r
		}
		if e, ok := opt.(ErrorHandler); ok {
			log.Printf("Error override")
			errorHandler = e
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if contentType != ReportContentType {
			errorHandler.Error(w, r, http.StatusUnsupportedMediaType, fmt.Errorf("Unsupported content type (expected %s)", ReportContentType))
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			errorHandler.Error(w, r, http.StatusBadRequest, err)
			return
		}

		rep := cspReport{}
		err = json.Unmarshal(body, &rep)
		if err != nil {
			errorHandler.Error(w, r, http.StatusBadRequest, err)
			return
		}

		err = reportHandler.Report(rep.Report)
		if err != nil {
			errorHandler.Error(w, r, http.StatusInternalServerError, err)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
