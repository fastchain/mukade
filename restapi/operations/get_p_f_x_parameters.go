// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
)

// NewGetPFXParams creates a new GetPFXParams object
//
// There are no default values defined in the spec.
func NewGetPFXParams() GetPFXParams {

	return GetPFXParams{}
}

// GetPFXParams contains all the bound params for the get p f x operation
// typically these are obtained from a http.Request
//
// swagger:parameters getPFX
type GetPFXParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*
	  Required: true
	  In: path
	*/
	CertificateID string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetPFXParams() beforehand.
func (o *GetPFXParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	rCertificateID, rhkCertificateID, _ := route.Params.GetOK("certificateId")
	if err := o.bindCertificateID(rCertificateID, rhkCertificateID, route.Formats); err != nil {
		res = append(res, err)
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindCertificateID binds and validates parameter CertificateID from path.
func (o *GetPFXParams) bindCertificateID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route
	o.CertificateID = raw

	return nil
}