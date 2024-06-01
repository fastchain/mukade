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
)

// NewRevokeCertificateParams creates a new RevokeCertificateParams object
// with the default values initialized.
func NewRevokeCertificateParams() *RevokeCertificateParams {
	var ()
	return &RevokeCertificateParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewRevokeCertificateParamsWithTimeout creates a new RevokeCertificateParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewRevokeCertificateParamsWithTimeout(timeout time.Duration) *RevokeCertificateParams {
	var ()
	return &RevokeCertificateParams{

		timeout: timeout,
	}
}

// NewRevokeCertificateParamsWithContext creates a new RevokeCertificateParams object
// with the default values initialized, and the ability to set a context for a request
func NewRevokeCertificateParamsWithContext(ctx context.Context) *RevokeCertificateParams {
	var ()
	return &RevokeCertificateParams{

		Context: ctx,
	}
}

// NewRevokeCertificateParamsWithHTTPClient creates a new RevokeCertificateParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewRevokeCertificateParamsWithHTTPClient(client *http.Client) *RevokeCertificateParams {
	var ()
	return &RevokeCertificateParams{
		HTTPClient: client,
	}
}

/*RevokeCertificateParams contains all the parameters to send to the API endpoint
for the revoke certificate operation typically these are written to a http.Request
*/
type RevokeCertificateParams struct {

	/*CertificateID*/
	CertificateID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the revoke certificate params
func (o *RevokeCertificateParams) WithTimeout(timeout time.Duration) *RevokeCertificateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the revoke certificate params
func (o *RevokeCertificateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the revoke certificate params
func (o *RevokeCertificateParams) WithContext(ctx context.Context) *RevokeCertificateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the revoke certificate params
func (o *RevokeCertificateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the revoke certificate params
func (o *RevokeCertificateParams) WithHTTPClient(client *http.Client) *RevokeCertificateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the revoke certificate params
func (o *RevokeCertificateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCertificateID adds the certificateID to the revoke certificate params
func (o *RevokeCertificateParams) WithCertificateID(certificateID string) *RevokeCertificateParams {
	o.SetCertificateID(certificateID)
	return o
}

// SetCertificateID adds the certificateId to the revoke certificate params
func (o *RevokeCertificateParams) SetCertificateID(certificateID string) {
	o.CertificateID = certificateID
}

// WriteToRequest writes these params to a swagger request
func (o *RevokeCertificateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param certificateId
	if err := r.SetPathParam("certificateId", o.CertificateID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
