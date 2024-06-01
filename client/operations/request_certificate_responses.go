// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/fastchain/mukade/models"
)

// RequestCertificateReader is a Reader for the RequestCertificate structure.
type RequestCertificateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RequestCertificateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRequestCertificateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRequestCertificateBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewRequestCertificateInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRequestCertificateOK creates a RequestCertificateOK with default headers values
func NewRequestCertificateOK() *RequestCertificateOK {
	return &RequestCertificateOK{}
}

/*RequestCertificateOK handles this case with default header values.

Certificate requested successfully
*/
type RequestCertificateOK struct {
	Payload *models.CertificateRequest
}

func (o *RequestCertificateOK) Error() string {
	return fmt.Sprintf("[POST /requests][%d] requestCertificateOK  %+v", 200, o.Payload)
}

func (o *RequestCertificateOK) GetPayload() *models.CertificateRequest {
	return o.Payload
}

func (o *RequestCertificateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CertificateRequest)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestCertificateBadRequest creates a RequestCertificateBadRequest with default headers values
func NewRequestCertificateBadRequest() *RequestCertificateBadRequest {
	return &RequestCertificateBadRequest{}
}

/*RequestCertificateBadRequest handles this case with default header values.

Invalid request
*/
type RequestCertificateBadRequest struct {
}

func (o *RequestCertificateBadRequest) Error() string {
	return fmt.Sprintf("[POST /requests][%d] requestCertificateBadRequest ", 400)
}

func (o *RequestCertificateBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRequestCertificateInternalServerError creates a RequestCertificateInternalServerError with default headers values
func NewRequestCertificateInternalServerError() *RequestCertificateInternalServerError {
	return &RequestCertificateInternalServerError{}
}

/*RequestCertificateInternalServerError handles this case with default header values.

Internal server error
*/
type RequestCertificateInternalServerError struct {
}

func (o *RequestCertificateInternalServerError) Error() string {
	return fmt.Sprintf("[POST /requests][%d] requestCertificateInternalServerError ", 500)
}

func (o *RequestCertificateInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
