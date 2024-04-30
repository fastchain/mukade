// Code generated by go-swagger; DO NOT EDIT.

package restapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
)

var (
	// SwaggerJSON embedded version of the swagger document used at generation time
	SwaggerJSON json.RawMessage
	// FlatSwaggerJSON embedded flattened version of the swagger document used at generation time
	FlatSwaggerJSON json.RawMessage
)

func init() {
	SwaggerJSON = json.RawMessage([]byte(`{
  "produces": [
    "application/json"
  ],
  "schemes": [
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "API for managing digital certificates issued by a Certificate Authority (CA).",
    "title": "Certificate Authority API",
    "version": "1.0.0"
  },
  "host": "ca.example.com",
  "basePath": "/api/v1",
  "paths": {
    "/certificates": {
      "post": {
        "description": "Request the issuance of a new digital certificate.",
        "summary": "Issue a new certificate",
        "operationId": "issueCertificate",
        "parameters": [
          {
            "name": "certificateRequest",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/CertificateRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Certificate issued successfully",
            "schema": {
              "$ref": "#/definitions/Certificate"
            }
          },
          "400": {
            "description": "Invalid request"
          },
          "500": {
            "description": "Internal server error"
          }
        }
      }
    },
    "/certificates/{certificateId}": {
      "get": {
        "description": "Retrieve the status and details of a specific certificate.",
        "summary": "Get certificate status",
        "operationId": "getCertificate",
        "parameters": [
          {
            "type": "string",
            "name": "certificateId",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "Successful retrieval of certificate data",
            "schema": {
              "$ref": "#/definitions/Certificate"
            }
          },
          "404": {
            "description": "Certificate not found"
          },
          "500": {
            "description": "Internal server error"
          }
        }
      },
      "delete": {
        "description": "Revoke a specific certificate.",
        "summary": "Revoke a certificate",
        "operationId": "revokeCertificate",
        "parameters": [
          {
            "type": "string",
            "name": "certificateId",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "Certificate revoked successfully"
          },
          "404": {
            "description": "Certificate not found"
          },
          "500": {
            "description": "Internal server error"
          }
        }
      }
    }
  },
  "definitions": {
    "Certificate": {
      "type": "object",
      "properties": {
        "certificateId": {
          "description": "Unique identifier for the certificate.",
          "type": "string"
        },
        "expiresOn": {
          "description": "Expiration date of the certificate.",
          "type": "string",
          "format": "date-time"
        },
        "issuedOn": {
          "description": "Date and time the certificate was issued.",
          "type": "string",
          "format": "date-time"
        },
        "status": {
          "description": "Current status of the certificate (e.g., active, revoked).",
          "type": "string"
        },
        "subject": {
          "description": "Name of the entity the certificate is issued to.",
          "type": "string"
        }
      }
    },
    "CertificateRequest": {
      "type": "object",
      "required": [
        "subject",
        "publicKey"
      ],
      "properties": {
        "publicKey": {
          "description": "Public key to be associated with the certificate.",
          "type": "string"
        },
        "subject": {
          "description": "Name of the entity requesting the certificate.",
          "type": "string"
        }
      }
    }
  }
}`))
	FlatSwaggerJSON = json.RawMessage([]byte(`{
  "produces": [
    "application/json"
  ],
  "schemes": [
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "API for managing digital certificates issued by a Certificate Authority (CA).",
    "title": "Certificate Authority API",
    "version": "1.0.0"
  },
  "host": "ca.example.com",
  "basePath": "/api/v1",
  "paths": {
    "/certificates": {
      "post": {
        "description": "Request the issuance of a new digital certificate.",
        "summary": "Issue a new certificate",
        "operationId": "issueCertificate",
        "parameters": [
          {
            "name": "certificateRequest",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/CertificateRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Certificate issued successfully",
            "schema": {
              "$ref": "#/definitions/Certificate"
            }
          },
          "400": {
            "description": "Invalid request"
          },
          "500": {
            "description": "Internal server error"
          }
        }
      }
    },
    "/certificates/{certificateId}": {
      "get": {
        "description": "Retrieve the status and details of a specific certificate.",
        "summary": "Get certificate status",
        "operationId": "getCertificate",
        "parameters": [
          {
            "type": "string",
            "name": "certificateId",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "Successful retrieval of certificate data",
            "schema": {
              "$ref": "#/definitions/Certificate"
            }
          },
          "404": {
            "description": "Certificate not found"
          },
          "500": {
            "description": "Internal server error"
          }
        }
      },
      "delete": {
        "description": "Revoke a specific certificate.",
        "summary": "Revoke a certificate",
        "operationId": "revokeCertificate",
        "parameters": [
          {
            "type": "string",
            "name": "certificateId",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "Certificate revoked successfully"
          },
          "404": {
            "description": "Certificate not found"
          },
          "500": {
            "description": "Internal server error"
          }
        }
      }
    }
  },
  "definitions": {
    "Certificate": {
      "type": "object",
      "properties": {
        "certificateId": {
          "description": "Unique identifier for the certificate.",
          "type": "string"
        },
        "expiresOn": {
          "description": "Expiration date of the certificate.",
          "type": "string",
          "format": "date-time"
        },
        "issuedOn": {
          "description": "Date and time the certificate was issued.",
          "type": "string",
          "format": "date-time"
        },
        "status": {
          "description": "Current status of the certificate (e.g., active, revoked).",
          "type": "string"
        },
        "subject": {
          "description": "Name of the entity the certificate is issued to.",
          "type": "string"
        }
      }
    },
    "CertificateRequest": {
      "type": "object",
      "required": [
        "subject",
        "publicKey"
      ],
      "properties": {
        "publicKey": {
          "description": "Public key to be associated with the certificate.",
          "type": "string"
        },
        "subject": {
          "description": "Name of the entity requesting the certificate.",
          "type": "string"
        }
      }
    }
  }
}`))
}