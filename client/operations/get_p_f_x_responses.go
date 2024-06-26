// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// GetPFXReader is a Reader for the GetPFX structure.
type GetPFXReader struct {
	formats strfmt.Registry
	writer  io.Writer
}

// ReadResponse reads a server response into the received o.
func (o *GetPFXReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPFXOK(o.writer)
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 404:
		result := NewGetPFXNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetPFXInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /certificates/{certificateId}/pfx] getPFX", response, response.Code())
	}
}

// NewGetPFXOK creates a GetPFXOK with default headers values
func NewGetPFXOK(writer io.Writer) *GetPFXOK {
	return &GetPFXOK{

		Payload: writer,
	}
}

/*
GetPFXOK describes a response with status code 200, with default header values.

Request processed
*/
type GetPFXOK struct {
	Payload io.Writer
}

// IsSuccess returns true when this get p f x o k response has a 2xx status code
func (o *GetPFXOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get p f x o k response has a 3xx status code
func (o *GetPFXOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get p f x o k response has a 4xx status code
func (o *GetPFXOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get p f x o k response has a 5xx status code
func (o *GetPFXOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get p f x o k response a status code equal to that given
func (o *GetPFXOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get p f x o k response
func (o *GetPFXOK) Code() int {
	return 200
}

func (o *GetPFXOK) Error() string {
	return fmt.Sprintf("[GET /certificates/{certificateId}/pfx][%d] getPFXOK  %+v", 200, o.Payload)
}

func (o *GetPFXOK) String() string {
	return fmt.Sprintf("[GET /certificates/{certificateId}/pfx][%d] getPFXOK  %+v", 200, o.Payload)
}

func (o *GetPFXOK) GetPayload() io.Writer {
	return o.Payload
}

func (o *GetPFXOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPFXNotFound creates a GetPFXNotFound with default headers values
func NewGetPFXNotFound() *GetPFXNotFound {
	return &GetPFXNotFound{}
}

/*
GetPFXNotFound describes a response with status code 404, with default header values.

Certificate not found
*/
type GetPFXNotFound struct {
}

// IsSuccess returns true when this get p f x not found response has a 2xx status code
func (o *GetPFXNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get p f x not found response has a 3xx status code
func (o *GetPFXNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get p f x not found response has a 4xx status code
func (o *GetPFXNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get p f x not found response has a 5xx status code
func (o *GetPFXNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get p f x not found response a status code equal to that given
func (o *GetPFXNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get p f x not found response
func (o *GetPFXNotFound) Code() int {
	return 404
}

func (o *GetPFXNotFound) Error() string {
	return fmt.Sprintf("[GET /certificates/{certificateId}/pfx][%d] getPFXNotFound ", 404)
}

func (o *GetPFXNotFound) String() string {
	return fmt.Sprintf("[GET /certificates/{certificateId}/pfx][%d] getPFXNotFound ", 404)
}

func (o *GetPFXNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetPFXInternalServerError creates a GetPFXInternalServerError with default headers values
func NewGetPFXInternalServerError() *GetPFXInternalServerError {
	return &GetPFXInternalServerError{}
}

/*
GetPFXInternalServerError describes a response with status code 500, with default header values.

Internal server error
*/
type GetPFXInternalServerError struct {
}

// IsSuccess returns true when this get p f x internal server error response has a 2xx status code
func (o *GetPFXInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get p f x internal server error response has a 3xx status code
func (o *GetPFXInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get p f x internal server error response has a 4xx status code
func (o *GetPFXInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get p f x internal server error response has a 5xx status code
func (o *GetPFXInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get p f x internal server error response a status code equal to that given
func (o *GetPFXInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get p f x internal server error response
func (o *GetPFXInternalServerError) Code() int {
	return 500
}

func (o *GetPFXInternalServerError) Error() string {
	return fmt.Sprintf("[GET /certificates/{certificateId}/pfx][%d] getPFXInternalServerError ", 500)
}

func (o *GetPFXInternalServerError) String() string {
	return fmt.Sprintf("[GET /certificates/{certificateId}/pfx][%d] getPFXInternalServerError ", 500)
}

func (o *GetPFXInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
