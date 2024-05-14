package mukadeoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	"fmt"
	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/fastchain/mukade/dbmodels"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
)

/*
GetArchiveLogic is logic to process GET request to dowload archive
*/
func SignRequestLogic(Flags MukadeFlags) func(params serveroperations.SignRequestParams) middleware.Responder {

	return func(params serveroperations.SignRequestParams) middleware.Responder {

		var csr dbmodels.CertificateRequest
		result:=dbmodels.DB.First(&csr, "lineid = ?", params.RequestID)
		if result.RowsAffected == 0 {
			//msg:="Line Not found "
			//return serveroperations.NewLineCreateInternalServerError().WithPayload(&dbmodels.Error{Message:&msg})
			panic("Line Not found ")
		}


		newCSR, err := helpers.ParseCSRPEM([]byte(csr.Raw))
		fmt.Println(newCSR.Subject)
		if err != nil {
			//return serveroperations.NewRequestCertificateOK().WithPayload(err)
			panic(err)
		}

		//Saving new line data

		//newCSR.PublicKey
		//newRequest := dbmodels.Certificate{Req: params.CertificateRequest.Raw }
		//CertificateRequest

		//kk := fmt.Sprint(newCSR.PublicKey)
		//cb := fmt.Sprint(newCSR.Subject)
		//
		//newRequest := dbmodels.CertificateRequest{
		//
		//	PublicKey: &kk,
		//	Raw:       params.CertificateRequest.Raw,
		//	Subject:   &cb,
		//}
		//result := dbmodels.DB.Create(&newRequest)
		//if result.Error != nil {
		//	//serveroperations.
		//	panic(result.Error.Error())
		//	//msg := result.Error.Error()
		//	return serveroperations.NewIssueCertificateInternalServerError()
		//}

		cfss := client.NewServer("http://127.0.0.1:8888")
		if cfss == nil {
			panic(cfss)

		}

		sign, err := cfss.Sign([]byte(csr.Raw))
		if sign == nil || err != nil {
			panic("expected error with sign function")
		}

		newCert, err := helpers.ParseCertificatePEM(sign)
		if err != nil {
			panic(newCert)
		}

		//fmt.Println(newCert)
		//var crt dbmodels.CertificateRequest
		//crt.Pem = string(helpers.EncodeCertificatePEM(newCert))
		//CFSS client
		return serveroperations.NewRequestCertificateOK()
		//return serveroperations.NewLineCheckInOK().WithPayload(&resident)
		////.WithPayload(archiveBodyReader)
	}
}
