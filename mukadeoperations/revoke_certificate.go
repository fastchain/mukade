package mukadeoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	"bytes"
	"encoding/json"
	"fmt"
	"github.com/fastchain/mukade/dbmodels"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
	"io"
	"net/http"
)

/*
GetArchiveLogic is logic to process GET request to dowload archive
*/
func RevokeCertificateLogic(Flags MukadeFlags) func(params serveroperations.RevokeCertificateParams) middleware.Responder {

	return func(params serveroperations.RevokeCertificateParams) middleware.Responder {

		//fmt.Println(params.RequestID)
		var crt dbmodels.Certificate
		result := dbmodels.DB.First(&crt, "id = ?", params.CertificateID)
		if result.RowsAffected == 0 {
			//msg:="Line Not found "
			//return serveroperations.NewLineCreateInternalServerError().WithPayload(&dbmodels.Error{Message:&msg})
			panic("Line Not found ")
		}

		//fmt.Println(csr.Raw)
		//pcrt, err := helpers.ParseCertificatesPEM([]byte(crt.Pem))
		//
		//if err != nil {
		//	//return serveroperations.NewRequestCertificateOK().WithPayload(err)
		//	panic(err)
		//}

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

		type jsonRevokeRequest struct {
			Serial string `json:"serial"`
			AKI    string `json:"authority_key_id"`
			Reason string `json:"reason"`
		}

		type CfssRequest struct {
			Number int    `json:"number"`
			Title  string `json:"title"`
		}

		jrr := jsonRevokeRequest{
			//Hosts:   hosts,
			Serial: crt.Serial,
			AKI:    crt.Aki,
			//Profile: "leaf",
			//Label:   cap.Label,
			//Bun
		}
		jrrout, err := json.Marshal(jrr)
		if err != nil {
			panic(err)
		}

		var resp *http.Response
		var body []byte

		resp, err = http.Post("http://127.0.0.1:8888/api/v1/cfssl/revoke", "application/json", bytes.NewReader(jrrout))
		if err != nil {
			panic(err)
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		//fmt.Println(string(body))

		resp, err = http.Get("http://127.0.0.1:8888/api/v1/cfssl/crl?expiry=72h")
		if err != nil {
			panic(err)
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		fmt.Println(body)

		//cfss := client.NewServer("http://127.0.0.1:8888")
		//if cfss == nil {
		//	panic(cfss)
		//
		//}
		//
		//revoke, err := cfss.Sign(jrrout)
		//if revoke == nil || err != nil {
		//	panic(err)
		//}

		//srout2, err := json.Marshal(newCert)
		//if err != nil {
		//	panic(err)
		//}

		return serveroperations.NewRevokeCertificateOK()
		//return serveroperations.NewLineCheckInOK()
		////.WithPayload(archiveBodyReader)
	}
}
