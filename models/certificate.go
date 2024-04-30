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

// Certificate certificate
//
// swagger:model Certificate
type Certificate struct {

	// Unique identifier for the certificate.
	CertificateID string `json:"certificateId,omitempty"`

	// Expiration date of the certificate.
	// Format: date-time
	ExpiresOn strfmt.DateTime `json:"expiresOn,omitempty"`

	// Date and time the certificate was issued.
	// Format: date-time
	IssuedOn strfmt.DateTime `json:"issuedOn,omitempty"`

	// Current status of the certificate (e.g., active, revoked).
	Status string `json:"status,omitempty"`

	// Name of the entity the certificate is issued to.
	Subject string `json:"subject,omitempty"`
}

// Validate validates this certificate
func (m *Certificate) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateExpiresOn(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIssuedOn(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Certificate) validateExpiresOn(formats strfmt.Registry) error {
	if swag.IsZero(m.ExpiresOn) { // not required
		return nil
	}

	if err := validate.FormatOf("expiresOn", "body", "date-time", m.ExpiresOn.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Certificate) validateIssuedOn(formats strfmt.Registry) error {
	if swag.IsZero(m.IssuedOn) { // not required
		return nil
	}

	if err := validate.FormatOf("issuedOn", "body", "date-time", m.IssuedOn.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this certificate based on context it is used
func (m *Certificate) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Certificate) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Certificate) UnmarshalBinary(b []byte) error {
	var res Certificate
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
