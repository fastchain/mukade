// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"github.com/fastchain/mukade/restapi/operations"
	"github.com/fastchain/mukadeoperations"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"log"
	"net/http"
)

//go:generate swagger generate server --target ../../mukade --name Mukade --spec ../swagger.yml --principal interface{}

var MukadeFlags mukadeoperations.MukadeFlags

func configureFlags(api *operations.MukadeAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

// decorator for a basic accesslogs
func addLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL, r.Header.Get("User-Agent"))
		next.ServeHTTP(w, r)
	})
}

//
////Get embeded static or FS
//func getFileSystem(useOS bool) http.FileSystem {
//	if useOS {
//		//log.Print("using live mode")
//		return http.FS(os.DirFS("./static"))
//	}
//
//	//log.Print("using embed mode")
//	fsys, err := fs.Sub(embededFiles, "static")
//	if err != nil {
//		panic(err)
//	}
//
//	return http.FS(fsys)
//}
//
////decorator for a basic FileServerMiddleware
//func fileServerMiddleware(next http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		if strings.HasPrefix(r.URL.Path, "/v1") {
//			next.ServeHTTP(w, r)
//		} else {
//			//box := packr.NewBox("../build/static")
//			//http.FileServer(http.Dir("./static")).ServeHTTP(w, r)
//			http.FileServer(getFileSystem(false)).ServeHTTP(w, r)
//			//http.FileServer(box)
//		}
//	})
//}

func configureAPI(api *operations.MukadeAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	//configuring DB
	//dbmodels.ConnectDataBase()

	//CFSS client
	//cfss := client.NewServer("http://127.0.0.1:8888")
	//if cfss == nil {
	//	panic(cfss)
	//
	//}

	api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()

	//if api.GetCertificateHandler == nil {
	//	api.GetCertificateHandler = operations.GetCertificateHandlerFunc(func(params operations.GetCertificateParams) middleware.Responder {
	//
	//		return middleware.NotImplemented("operation operations.GetCertificateParams has not yet been implemented")
	//	})
	//}
	//if api.IssueCertificateHandler == nil {
	//	api.IssueCertificateHandler = operations.IssueCertificateHandlerFunc(func(params operations.IssueCertificateParams) middleware.Responder {
	//		sign, err := cfss.Sign([]byte{5, 5, 5, 5})
	//		if sign != nil || err == nil {
	//			panic("expected error with sign function")
	//		}
	//		return middleware.NotImplemented(string(sign))
	//	})
	//}
	//if api.RevokeCertificateHandler == nil {
	//	api.RevokeCertificateHandler = operations.RevokeCertificateHandlerFunc(func(params operations.RevokeCertificateParams) middleware.Responder {
	//		return middleware.NotImplemented("operation operations.RevokeCertificate has not yet been implemented")
	//	})
	//}

	api.IssueCertificateHandler = operations.IssueCertificateHandlerFunc(mukadeoperations.IssueCertificateLogic(MukadeFlags))

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix".
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation.
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics.
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
