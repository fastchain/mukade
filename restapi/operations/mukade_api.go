// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/runtime/security"
	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewMukadeAPI creates a new Mukade instance
func NewMukadeAPI(spec *loads.Document) *MukadeAPI {
	return &MukadeAPI{
		handlers:            make(map[string]map[string]http.Handler),
		formats:             strfmt.Default,
		defaultConsumes:     "application/json",
		defaultProduces:     "application/json",
		customConsumers:     make(map[string]runtime.Consumer),
		customProducers:     make(map[string]runtime.Producer),
		PreServerShutdown:   func() {},
		ServerShutdown:      func() {},
		spec:                spec,
		useSwaggerUI:        false,
		ServeError:          errors.ServeError,
		BasicAuthenticator:  security.BasicAuth,
		APIKeyAuthenticator: security.APIKeyAuth,
		BearerAuthenticator: security.BearerAuth,

		JSONConsumer: runtime.JSONConsumer(),

		BinProducer:  runtime.ByteStreamProducer(),
		JSONProducer: runtime.JSONProducer(),

		GetCertificateHandler: GetCertificateHandlerFunc(func(params GetCertificateParams) middleware.Responder {
			return middleware.NotImplemented("operation GetCertificate has not yet been implemented")
		}),
		GetPFXHandler: GetPFXHandlerFunc(func(params GetPFXParams) middleware.Responder {
			return middleware.NotImplemented("operation GetPFX has not yet been implemented")
		}),
		IssueCertificateHandler: IssueCertificateHandlerFunc(func(params IssueCertificateParams) middleware.Responder {
			return middleware.NotImplemented("operation IssueCertificate has not yet been implemented")
		}),
		RequestCRLHandler: RequestCRLHandlerFunc(func(params RequestCRLParams) middleware.Responder {
			return middleware.NotImplemented("operation RequestCRL has not yet been implemented")
		}),
		RequestCertificateHandler: RequestCertificateHandlerFunc(func(params RequestCertificateParams) middleware.Responder {
			return middleware.NotImplemented("operation RequestCertificate has not yet been implemented")
		}),
		RevokeCertificateHandler: RevokeCertificateHandlerFunc(func(params RevokeCertificateParams) middleware.Responder {
			return middleware.NotImplemented("operation RevokeCertificate has not yet been implemented")
		}),
		SignRequestHandler: SignRequestHandlerFunc(func(params SignRequestParams) middleware.Responder {
			return middleware.NotImplemented("operation SignRequest has not yet been implemented")
		}),
	}
}

/*MukadeAPI API for managing digital certificates issued by a Certificate Authority (CA). */
type MukadeAPI struct {
	spec            *loads.Document
	context         *middleware.Context
	handlers        map[string]map[string]http.Handler
	formats         strfmt.Registry
	customConsumers map[string]runtime.Consumer
	customProducers map[string]runtime.Producer
	defaultConsumes string
	defaultProduces string
	Middleware      func(middleware.Builder) http.Handler
	useSwaggerUI    bool

	// BasicAuthenticator generates a runtime.Authenticator from the supplied basic auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	BasicAuthenticator func(security.UserPassAuthentication) runtime.Authenticator

	// APIKeyAuthenticator generates a runtime.Authenticator from the supplied token auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	APIKeyAuthenticator func(string, string, security.TokenAuthentication) runtime.Authenticator

	// BearerAuthenticator generates a runtime.Authenticator from the supplied bearer token auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	BearerAuthenticator func(string, security.ScopedTokenAuthentication) runtime.Authenticator

	// JSONConsumer registers a consumer for the following mime types:
	//   - application/json
	JSONConsumer runtime.Consumer

	// BinProducer registers a producer for the following mime types:
	//   - application/octet-stream
	BinProducer runtime.Producer
	// JSONProducer registers a producer for the following mime types:
	//   - application/json
	JSONProducer runtime.Producer

	// GetCertificateHandler sets the operation handler for the get certificate operation
	GetCertificateHandler GetCertificateHandler
	// GetPFXHandler sets the operation handler for the get p f x operation
	GetPFXHandler GetPFXHandler
	// IssueCertificateHandler sets the operation handler for the issue certificate operation
	IssueCertificateHandler IssueCertificateHandler
	// RequestCRLHandler sets the operation handler for the request c r l operation
	RequestCRLHandler RequestCRLHandler
	// RequestCertificateHandler sets the operation handler for the request certificate operation
	RequestCertificateHandler RequestCertificateHandler
	// RevokeCertificateHandler sets the operation handler for the revoke certificate operation
	RevokeCertificateHandler RevokeCertificateHandler
	// SignRequestHandler sets the operation handler for the sign request operation
	SignRequestHandler SignRequestHandler

	// ServeError is called when an error is received, there is a default handler
	// but you can set your own with this
	ServeError func(http.ResponseWriter, *http.Request, error)

	// PreServerShutdown is called before the HTTP(S) server is shutdown
	// This allows for custom functions to get executed before the HTTP(S) server stops accepting traffic
	PreServerShutdown func()

	// ServerShutdown is called when the HTTP(S) server is shut down and done
	// handling all active connections and does not accept connections any more
	ServerShutdown func()

	// Custom command line argument groups with their descriptions
	CommandLineOptionsGroups []swag.CommandLineOptionsGroup

	// User defined logger function.
	Logger func(string, ...interface{})
}

// UseRedoc for documentation at /docs
func (o *MukadeAPI) UseRedoc() {
	o.useSwaggerUI = false
}

// UseSwaggerUI for documentation at /docs
func (o *MukadeAPI) UseSwaggerUI() {
	o.useSwaggerUI = true
}

// SetDefaultProduces sets the default produces media type
func (o *MukadeAPI) SetDefaultProduces(mediaType string) {
	o.defaultProduces = mediaType
}

// SetDefaultConsumes returns the default consumes media type
func (o *MukadeAPI) SetDefaultConsumes(mediaType string) {
	o.defaultConsumes = mediaType
}

// SetSpec sets a spec that will be served for the clients.
func (o *MukadeAPI) SetSpec(spec *loads.Document) {
	o.spec = spec
}

// DefaultProduces returns the default produces media type
func (o *MukadeAPI) DefaultProduces() string {
	return o.defaultProduces
}

// DefaultConsumes returns the default consumes media type
func (o *MukadeAPI) DefaultConsumes() string {
	return o.defaultConsumes
}

// Formats returns the registered string formats
func (o *MukadeAPI) Formats() strfmt.Registry {
	return o.formats
}

// RegisterFormat registers a custom format validator
func (o *MukadeAPI) RegisterFormat(name string, format strfmt.Format, validator strfmt.Validator) {
	o.formats.Add(name, format, validator)
}

// Validate validates the registrations in the MukadeAPI
func (o *MukadeAPI) Validate() error {
	var unregistered []string

	if o.JSONConsumer == nil {
		unregistered = append(unregistered, "JSONConsumer")
	}

	if o.BinProducer == nil {
		unregistered = append(unregistered, "BinProducer")
	}
	if o.JSONProducer == nil {
		unregistered = append(unregistered, "JSONProducer")
	}

	if o.GetCertificateHandler == nil {
		unregistered = append(unregistered, "GetCertificateHandler")
	}
	if o.GetPFXHandler == nil {
		unregistered = append(unregistered, "GetPFXHandler")
	}
	if o.IssueCertificateHandler == nil {
		unregistered = append(unregistered, "IssueCertificateHandler")
	}
	if o.RequestCRLHandler == nil {
		unregistered = append(unregistered, "RequestCRLHandler")
	}
	if o.RequestCertificateHandler == nil {
		unregistered = append(unregistered, "RequestCertificateHandler")
	}
	if o.RevokeCertificateHandler == nil {
		unregistered = append(unregistered, "RevokeCertificateHandler")
	}
	if o.SignRequestHandler == nil {
		unregistered = append(unregistered, "SignRequestHandler")
	}

	if len(unregistered) > 0 {
		return fmt.Errorf("missing registration: %s", strings.Join(unregistered, ", "))
	}

	return nil
}

// ServeErrorFor gets a error handler for a given operation id
func (o *MukadeAPI) ServeErrorFor(operationID string) func(http.ResponseWriter, *http.Request, error) {
	return o.ServeError
}

// AuthenticatorsFor gets the authenticators for the specified security schemes
func (o *MukadeAPI) AuthenticatorsFor(schemes map[string]spec.SecurityScheme) map[string]runtime.Authenticator {
	return nil
}

// Authorizer returns the registered authorizer
func (o *MukadeAPI) Authorizer() runtime.Authorizer {
	return nil
}

// ConsumersFor gets the consumers for the specified media types.
// MIME type parameters are ignored here.
func (o *MukadeAPI) ConsumersFor(mediaTypes []string) map[string]runtime.Consumer {
	result := make(map[string]runtime.Consumer, len(mediaTypes))
	for _, mt := range mediaTypes {
		switch mt {
		case "application/json":
			result["application/json"] = o.JSONConsumer
		}

		if c, ok := o.customConsumers[mt]; ok {
			result[mt] = c
		}
	}
	return result
}

// ProducersFor gets the producers for the specified media types.
// MIME type parameters are ignored here.
func (o *MukadeAPI) ProducersFor(mediaTypes []string) map[string]runtime.Producer {
	result := make(map[string]runtime.Producer, len(mediaTypes))
	for _, mt := range mediaTypes {
		switch mt {
		case "application/octet-stream":
			result["application/octet-stream"] = o.BinProducer
		case "application/json":
			result["application/json"] = o.JSONProducer
		}

		if p, ok := o.customProducers[mt]; ok {
			result[mt] = p
		}
	}
	return result
}

// HandlerFor gets a http.Handler for the provided operation method and path
func (o *MukadeAPI) HandlerFor(method, path string) (http.Handler, bool) {
	if o.handlers == nil {
		return nil, false
	}
	um := strings.ToUpper(method)
	if _, ok := o.handlers[um]; !ok {
		return nil, false
	}
	if path == "/" {
		path = ""
	}
	h, ok := o.handlers[um][path]
	return h, ok
}

// Context returns the middleware context for the mukade API
func (o *MukadeAPI) Context() *middleware.Context {
	if o.context == nil {
		o.context = middleware.NewRoutableContext(o.spec, o, nil)
	}

	return o.context
}

func (o *MukadeAPI) initHandlerCache() {
	o.Context() // don't care about the result, just that the initialization happened
	if o.handlers == nil {
		o.handlers = make(map[string]map[string]http.Handler)
	}

	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/certificates/{certificateId}"] = NewGetCertificate(o.context, o.GetCertificateHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/certificates/{certificateId}/pfx"] = NewGetPFX(o.context, o.GetPFXHandler)
	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/certificates"] = NewIssueCertificate(o.context, o.IssueCertificateHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/crl.crl"] = NewRequestCRL(o.context, o.RequestCRLHandler)
	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/requests"] = NewRequestCertificate(o.context, o.RequestCertificateHandler)
	if o.handlers["DELETE"] == nil {
		o.handlers["DELETE"] = make(map[string]http.Handler)
	}
	o.handlers["DELETE"]["/certificates/{certificateId}"] = NewRevokeCertificate(o.context, o.RevokeCertificateHandler)
	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/requests/{requestId}"] = NewSignRequest(o.context, o.SignRequestHandler)
}

// Serve creates a http handler to serve the API over HTTP
// can be used directly in http.ListenAndServe(":8000", api.Serve(nil))
func (o *MukadeAPI) Serve(builder middleware.Builder) http.Handler {
	o.Init()

	if o.Middleware != nil {
		return o.Middleware(builder)
	}
	if o.useSwaggerUI {
		return o.context.APIHandlerSwaggerUI(builder)
	}
	return o.context.APIHandler(builder)
}

// Init allows you to just initialize the handler cache, you can then recompose the middleware as you see fit
func (o *MukadeAPI) Init() {
	if len(o.handlers) == 0 {
		o.initHandlerCache()
	}
}

// RegisterConsumer allows you to add (or override) a consumer for a media type.
func (o *MukadeAPI) RegisterConsumer(mediaType string, consumer runtime.Consumer) {
	o.customConsumers[mediaType] = consumer
}

// RegisterProducer allows you to add (or override) a producer for a media type.
func (o *MukadeAPI) RegisterProducer(mediaType string, producer runtime.Producer) {
	o.customProducers[mediaType] = producer
}

// AddMiddlewareFor adds a http middleware to existing handler
func (o *MukadeAPI) AddMiddlewareFor(method, path string, builder middleware.Builder) {
	um := strings.ToUpper(method)
	if path == "/" {
		path = ""
	}
	o.Init()
	if h, ok := o.handlers[um][path]; ok {
		o.handlers[um][path] = builder(h)
	}
}
