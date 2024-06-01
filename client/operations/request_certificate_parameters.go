// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/fastchain/mukade/models"
)

// NewRequestCertificateParams creates a new RequestCertificateParams object
// with the default values initialized.
func NewRequestCertificateParams() *RequestCertificateParams {
	var ()
	return &RequestCertificateParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewRequestCertificateParamsWithTimeout creates a new RequestCertificateParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewRequestCertificateParamsWithTimeout(timeout time.Duration) *RequestCertificateParams {
	var ()
	return &RequestCertificateParams{

		timeout: timeout,
	}
}

// NewRequestCertificateParamsWithContext creates a new RequestCertificateParams object
// with the default values initialized, and the ability to set a context for a request
func NewRequestCertificateParamsWithContext(ctx context.Context) *RequestCertificateParams {
	var ()
	return &RequestCertificateParams{

		Context: ctx,
	}
}

// NewRequestCertificateParamsWithHTTPClient creates a new RequestCertificateParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewRequestCertificateParamsWithHTTPClient(client *http.Client) *RequestCertificateParams {
	var ()
	return &RequestCertificateParams{
		HTTPClient: client,
	}
}

/*RequestCertificateParams contains all the parameters to send to the API endpoint
for the request certificate operation typically these are written to a http.Request
*/
type RequestCertificateParams struct {

	/*CertificateRequest*/
	CertificateRequest *models.CertificateRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the request certificate params
func (o *RequestCertificateParams) WithTimeout(timeout time.Duration) *RequestCertificateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the request certificate params
func (o *RequestCertificateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the request certificate params
func (o *RequestCertificateParams) WithContext(ctx context.Context) *RequestCertificateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the request certificate params
func (o *RequestCertificateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the request certificate params
func (o *RequestCertificateParams) WithHTTPClient(client *http.Client) *RequestCertificateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the request certificate params
func (o *RequestCertificateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCertificateRequest adds the certificateRequest to the request certificate params
func (o *RequestCertificateParams) WithCertificateRequest(certificateRequest *models.CertificateRequest) *RequestCertificateParams {
	o.SetCertificateRequest(certificateRequest)
	return o
}

// SetCertificateRequest adds the certificateRequest to the request certificate params
func (o *RequestCertificateParams) SetCertificateRequest(certificateRequest *models.CertificateRequest) {
	o.CertificateRequest = certificateRequest
}

// WriteToRequest writes these params to a swagger request
func (o *RequestCertificateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.CertificateRequest != nil {
		if err := r.SetBodyParam(o.CertificateRequest); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
