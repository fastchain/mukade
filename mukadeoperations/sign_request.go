package mukadeoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/fastchain/mukade/dbmodels"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
	"io"
	"math/big"
	"net/http"
)

/*
GetArchiveLogic is logic to process GET request to dowload archive
*/
func SignRequestLogic(Flags MukadeFlags) func(params serveroperations.SignRequestParams) middleware.Responder {

	return func(params serveroperations.SignRequestParams) middleware.Responder {

		//fmt.Println(params.RequestID)
		var csr dbmodels.CertificateRequest
		result := dbmodels.DB.First(&csr, "id = ?", params.RequestID)
		if result.RowsAffected == 0 {
			//msg:="Line Not found "
			//return serveroperations.NewLineCreateInternalServerError().WithPayload(&dbmodels.Error{Message:&msg})
			panic("Line Not found ")
		}

		//fmt.Println(csr.Raw)
		//csrp, err := helpers.ParseCSRPEM([]byte(csr.Raw))
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

		type CfssRequest struct {
			Number int    `json:"number"`
			Title  string `json:"title"`
		}

		type jsonSignRequest struct {
			Hostname string          `json:"hostname"`
			Hosts    []string        `json:"hosts"`
			Request  string          `json:"certificate_request"`
			Subject  *signer.Subject `json:"subject,omitempty"`
			Profile  string          `json:"profile"`
			Label    string          `json:"label"`
			Serial   *big.Int        `json:"serial,omitempty"`
			Bundle   bool            `json:"bundle"`
		}
		sr := jsonSignRequest{
			Request: csr.Raw,
			Bundle:  true,
		}

		//sr := &signer.SignRequest{
		//	Request: csr.Raw,
		//}
		srout, err := json.Marshal(sr)
		if err != nil {
			panic(err)
		}

		cfss := client.NewServer("http://127.0.0.1:8888")
		if cfss == nil {
			panic(cfss)

		}

		sign, err := cfss.Sign(srout)
		if sign == nil || err != nil {
			panic(err)
		}

		//fmt.Println(string(sign))
		newCert, err := helpers.ParseCertificatePEM(sign)
		if err != nil {
			panic(newCert)
		}

		//bundle request
		type jsonBundleRequest struct {
			Certificate string `json:"certificate"`
		}

		jbr := jsonBundleRequest{
			//Hosts:   hosts,
			Certificate: string(sign),
			//Profile: "leaf",
			//Label:   cap.Label,
			//Bun
		}
		jbrout, err := json.Marshal(jbr)
		if err != nil {
			panic(err)
		}

		var resp *http.Response
		var body []byte

		resp, err = http.Post("http://127.0.0.1:8888/api/v1/cfssl/bundle", "application/json", bytes.NewReader(jbrout))
		if err != nil {
			panic(err)
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		// Variable to hold the unmarshaled data
		var bundle map[string]interface{}

		// Unmarshal the JSON data into the map
		err = json.Unmarshal(body, &bundle)
		if err != nil {
			panic(err)
		}

		//fmt.Println(bundle["result"].(map[string]interface{})["bundle"])

		//srout2, err := json.Marshal(newCert)
		//if err != nil {
		//	panic(err)
		//}

		//pp := csrp.PublicKey
		//rsaPublickey, _ := pp.(*rsa.PublicKey)
		//
		////fmt.Println(newCert.AuthorityKeyId)
		//h := sha1.New()
		//h.Write(rsaPublickey.N.Bytes())
		//id := hex.EncodeToString(h.Sum(nil))

		newCertificate := dbmodels.Certificate{

			Pem:     string(helpers.EncodeCertificatePEM(newCert)),
			Subject: newCert.Subject.String(),
			Req:     csr.Raw,
			Serial:  newCert.SerialNumber.String(),
			ID:      params.RequestID,
			Aki:     hex.EncodeToString(newCert.AuthorityKeyId),
			Bundle:  bundle["result"].(map[string]interface{})["bundle"].(string),
		}
		result = dbmodels.DB.Create(&newCertificate)
		if result.Error != nil {
			//serveroperations.
			panic(result.Error.Error())
			//msg := result.Error.Error()
			//return serveroperations.NewIssueCertificateInternalServerError()
		}
		//fmt.Println(string(helpers.EncodeCertificatePEM(newCert)))
		//var crt dbmodels.CertificateRequest
		//crt.Pem = string(helpers.EncodeCertificatePEM(newCert))
		//CFSS client
		return serveroperations.NewRequestCertificateOK() //.WithPayload(&newCert.Raw)
		//return serveroperations.NewLineCheckInOK().WithPayload(&resident)
		////.WithPayload(archiveBodyReader)
	}
}
