// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PFX p f x
//
// swagger:model PFX
type PFX struct {

	// PFX
	// Required: true
	Raw *string `json:"raw"`
}

// Validate validates this p f x
func (m *PFX) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRaw(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PFX) validateRaw(formats strfmt.Registry) error {

	if err := validate.Required("raw", "body", m.Raw); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this p f x based on context it is used
func (m *PFX) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PFX) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PFX) UnmarshalBinary(b []byte) error {
	var res PFX
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}