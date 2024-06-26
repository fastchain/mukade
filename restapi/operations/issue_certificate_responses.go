// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/fastchain/mukade/models"
)

// IssueCertificateOKCode is the HTTP code returned for type IssueCertificateOK
const IssueCertificateOKCode int = 200

/*
IssueCertificateOK Certificate issued successfully

swagger:response issueCertificateOK
*/
type IssueCertificateOK struct {

	/*
	  In: Body
	*/
	Payload *models.Certificate `json:"body,omitempty"`
}

// NewIssueCertificateOK creates IssueCertificateOK with default headers values
func NewIssueCertificateOK() *IssueCertificateOK {

	return &IssueCertificateOK{}
}

// WithPayload adds the payload to the issue certificate o k response
func (o *IssueCertificateOK) WithPayload(payload *models.Certificate) *IssueCertificateOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the issue certificate o k response
func (o *IssueCertificateOK) SetPayload(payload *models.Certificate) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *IssueCertificateOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// IssueCertificateBadRequestCode is the HTTP code returned for type IssueCertificateBadRequest
const IssueCertificateBadRequestCode int = 400

/*
IssueCertificateBadRequest Invalid request

swagger:response issueCertificateBadRequest
*/
type IssueCertificateBadRequest struct {
}

// NewIssueCertificateBadRequest creates IssueCertificateBadRequest with default headers values
func NewIssueCertificateBadRequest() *IssueCertificateBadRequest {

	return &IssueCertificateBadRequest{}
}

// WriteResponse to the client
func (o *IssueCertificateBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(400)
}

// IssueCertificateInternalServerErrorCode is the HTTP code returned for type IssueCertificateInternalServerError
const IssueCertificateInternalServerErrorCode int = 500

/*
IssueCertificateInternalServerError Internal server error

swagger:response issueCertificateInternalServerError
*/
type IssueCertificateInternalServerError struct {
}

// NewIssueCertificateInternalServerError creates IssueCertificateInternalServerError with default headers values
func NewIssueCertificateInternalServerError() *IssueCertificateInternalServerError {

	return &IssueCertificateInternalServerError{}
}

// WriteResponse to the client
func (o *IssueCertificateInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(500)
}
