package mukadeoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	"fmt"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/fastchain/mukade/dbmodels"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
)

/*
GetArchiveLogic is logic to process GET request to dowload archive
*/
func IssueCertificateLogic(Flags MukadeFlags) func(params serveroperations.IssueCertificateParams) middleware.Responder {

	return func(params serveroperations.IssueCertificateParams) middleware.Responder {

		newCSR, err := helpers.ParseCSRPEM([]byte(params.CertificateRequest.Raw))
		fmt.Println(params.CertificateRequest.Raw)
		if err != nil {
			panic(err)
		}

		//Saving new line data

		//newCSR.PublicKey
		//newRequest := dbmodels.Certificate{Req: params.CertificateRequest.Raw }
		//CertificateRequest

		kk := fmt.Sprint(newCSR.PublicKey)


		newRequest := dbmodels.CertificateRequest{Subject: newCSR.Subject.Organization[0],
			PublicKey: kk,
			Raw:       params.CertificateRequest.Raw,

		}
		result := dbmodels.DB.Create(&newRequest)
		if result.Error != nil {
			//serveroperations.
			panic(result.Error.Error())
			//msg := result.Error.Error()
			return serveroperations.NewIssueCertificateInternalServerError()
		}

		//cfss := client.NewServer("http://127.0.0.1:8888")
		//if cfss == nil {
		//	panic(cfss)
		//
		//}
		//
		//sign, err := cfss.Sign([]byte(params.CertificateRequest.Raw))
		//if sign == nil || err != nil {
		//	panic("expected error with sign function")
		//}
		//
		//newCert, err := helpers.ParseCertificatePEM(sign)
		//if err != nil {
		//	panic(newCert)
		//}
		//
		////fmt.Println(newCert)
		//var crt dbmodels.CertificateRequest
		//crt.Pem = string(helpers.EncodeCertificatePEM(newCert))
		////CFSS client
		return serveroperations.NewIssueCertificateOK()
		//return serveroperations.NewLineCheckInOK().WithPayload(&resident)
		////.WithPayload(archiveBodyReader)
	}
}
