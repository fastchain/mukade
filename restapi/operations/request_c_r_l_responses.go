// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"io"
	"net/http"

	"github.com/go-openapi/runtime"
)

// RequestCRLOKCode is the HTTP code returned for type RequestCRLOK
const RequestCRLOKCode int = 200

/*
RequestCRLOK Request processed

swagger:response requestCRLOK
*/
type RequestCRLOK struct {

	/*
	  In: Body
	*/
	Payload io.ReadCloser `json:"body,omitempty"`
}

// NewRequestCRLOK creates RequestCRLOK with default headers values
func NewRequestCRLOK() *RequestCRLOK {

	return &RequestCRLOK{}
}

// WithPayload adds the payload to the request c r l o k response
func (o *RequestCRLOK) WithPayload(payload io.ReadCloser) *RequestCRLOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the request c r l o k response
func (o *RequestCRLOK) SetPayload(payload io.ReadCloser) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *RequestCRLOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}

// RequestCRLBadRequestCode is the HTTP code returned for type RequestCRLBadRequest
const RequestCRLBadRequestCode int = 400

/*
RequestCRLBadRequest Invalid request

swagger:response requestCRLBadRequest
*/
type RequestCRLBadRequest struct {
}

// NewRequestCRLBadRequest creates RequestCRLBadRequest with default headers values
func NewRequestCRLBadRequest() *RequestCRLBadRequest {

	return &RequestCRLBadRequest{}
}

// WriteResponse to the client
func (o *RequestCRLBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(400)
}

// RequestCRLInternalServerErrorCode is the HTTP code returned for type RequestCRLInternalServerError
const RequestCRLInternalServerErrorCode int = 500

/*
RequestCRLInternalServerError Internal server error

swagger:response requestCRLInternalServerError
*/
type RequestCRLInternalServerError struct {
}

// NewRequestCRLInternalServerError creates RequestCRLInternalServerError with default headers values
func NewRequestCRLInternalServerError() *RequestCRLInternalServerError {

	return &RequestCRLInternalServerError{}
}

// WriteResponse to the client
func (o *RequestCRLInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(500)
}
