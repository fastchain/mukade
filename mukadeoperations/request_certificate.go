package mukadeoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	"crypto/sha1"
	"fmt"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/fastchain/mukade/dbmodels"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	"github.com/go-openapi/runtime/middleware"

	"crypto/x509"
)

/*
GetArchiveLogic is logic to process GET request to dowload archive
*/
func RequestCertificateLogic(Flags MukadeFlags) func(params serveroperations.RequestCertificateParams) middleware.Responder {

	return func(params serveroperations.RequestCertificateParams) middleware.Responder {

		//replaced := strings.ReplaceAll(params.CertificateRequest.Raw, "\\n", "")
		//fmt.Println(replaced)
		var newRequest  dbmodels.CertificateRequest
		if len(params.CertificateRequest.Raw)!=0 {
			newCSR, err := helpers.ParseCSRPEM([]byte(params.CertificateRequest.Raw))
			if err != nil {
				//return serveroperations.NewRequestCertificateOK().WithPayload(err)
				panic(err)
			}

			//Saving new line data

			//newCSR.PublicKey
			//newRequest := dbmodels.Certificate{Req: params.CertificateRequest.Raw }
			//CertificateRequest

			pk := fmt.Sprint(newCSR.PublicKey)
			cb := fmt.Sprint(newCSR.Subject)

			//kk, _ := newCSR.PublicKey.(*rsa.PublicKey)
			//
			//h := sha1.New()
			//h.Write(kk.N.Bytes())
			//id := hex.EncodeToString(h.Sum(nil))

			// Extract the public key from the CSR
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(newCSR.PublicKey)
			if err != nil {
				panic(err)
			}

			// Compute the public key identifier (SHA-1 hash of the public key)
			pubKeyID := sha1.Sum(pubKeyBytes)
			pubKeyIDStr := fmt.Sprintf("%x", pubKeyID)

			newRequest = dbmodels.CertificateRequest{

				PublicKey: pk,
				Raw:       params.CertificateRequest.Raw,
				Subject:   cb,
				ID:        pubKeyIDStr,
				Cn:        params.CertificateRequest.Cn,
			}
		} else {



			// Compute the public key identifier (SHA-1 hash of the public key)
			pubKeyID := sha1.Sum([]byte(fmt.Sprint(params.CertificateRequest.Cn)))
			pubKeyIDStr := fmt.Sprintf("%x", pubKeyID)

			newRequest = dbmodels.CertificateRequest{

				Raw:       params.CertificateRequest.Raw,
				ID:        pubKeyIDStr,
				Cn:        params.CertificateRequest.Cn,
			}
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
		return serveroperations.NewRequestCertificateOK().WithPayload(&newRequest)
		//return serveroperations.NewLineCheckInOK().WithPayload(&resident)
		////.WithPayload(archiveBodyReader)
	}
}
