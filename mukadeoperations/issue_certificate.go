package mukadetoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/fastchain/mukade/dbmodels"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	middleware "github.com/go-openapi/runtime/middleware"
)

/*
GetArchiveLogic is logic to process GET request to dowload archive
*/
func IssueCertificateLogic(Flags MukadeFlags) func(params serveroperations.IssueCertificateParams) middleware.Responder {

	return func(params serveroperations.IssueCertificateParams) middleware.Responder {

		cfss := client.NewServer("http://127.0.0.1:8888")
		if cfss == nil {
			panic(cfss)

		}
		sign, err := cfss.Sign([]byte{5, 5, 5, 5})
		if sign != nil || err == nil {
			panic("expected error with sign function")
		}

		var crt dbmodels.Certificate
		//CFSS client
		return serveroperations.NewIssueCertificateOK().WithPayload(&crt)
		//return serveroperations.NewLineCheckInOK().WithPayload(&resident)
		////.WithPayload(archiveBodyReader)
	}
}
