package mukadeoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	//"github.com/cloudflare/cfssl/whitelist"
	"github.com/fastchain/mukade/dbmodels"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
	"log"
	"os"

	//"golang.org/x/crypto/pkcs12"
	"io"
	"math/big"
	"net/http"

	"software.sslmate.com/src/go-pkcs12"
)

// loadPEMCerts loads a bundle of intermediate certificates from a PEM file
func loadPEMCerts(bundle string) ([]*x509.Certificate, error) {
	//certPEM, err := os.ReadFile(certFile)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to read cert file: %w", err)
	//}

	certPEM:= []byte(bundle)
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		certPEM = rest
	}

	return certs, nil
}


/*
GetArchiveLogic is logic to process GET request to dowload archive
*/
func SignRequestLogic(Flags MukadeFlags) func(params serveroperations.SignRequestParams) middleware.Responder {

	return func(params serveroperations.SignRequestParams) middleware.Responder {

		//fmt.Println(params.RequestID)
		var sign []byte
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

		if len(csr.Raw)>0 {
			sign, err = cfss.Sign(srout)
			if sign == nil || err != nil {
				panic(err)
			}
		} else {

			type cfsslRequestName struct {
				C string `json:"c"`
				ST string `json:"st"`
				L string `json:"l"`
				O string `json:"o"`
			}
			type cfsslRequest struct {
				Hosts []string `json:"hosts"`
				Names []cfsslRequestName `json:"names"`
			}
			type jsonGenerateCertificateAndKey struct {
				Request cfsslRequest `json:"request"`
				Cn    string `json:"cn"`
			}

			jcr := jsonGenerateCertificateAndKey{
				//Hosts:   hosts,
				Cn: fmt.Sprint(csr.Cn),
				Request: cfsslRequest{
					Names: []cfsslRequestName{{C:"us",ST: "CN",L:"ND",O: "SS"}},
					Hosts: []string{"www.example.com"},
				},
				//Profile: "leaf",
				//Label:   cap.Label,
				//Bun
			}

			jcrout, err := json.Marshal(jcr)
			if err != nil {
				panic(err)
			}

			resp, err := http.Post("http://127.0.0.1:8888/api/v1/cfssl/newcert", "application/json", bytes.NewReader(jcrout))
			if err != nil {
				panic(err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				panic(err)
			}

			fmt.Println(string(body))

			//result := map[string]interface{}{
			//	"private_key":         string(key),
			//	"certificate_request": string(csr),
			//	"certificate":         string(certBytes),
			//	"sums": map[string]Sum{
			//		"certificate_request": reqSum,
			//		"certificate":         certSum,
			//	},
			//}

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

		nicebundle:= bundle["result"].(map[string]interface{})["bundle"].(string)
		//password := "1234"


		intermediates, err := loadPEMCerts(nicebundle)
		if err != nil {
			log.Fatalf("Failed to load intermediate certs: %v", err)
		}

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}
		pfxData, err := pkcs12.Legacy.Encode( priv, intermediates[0], intermediates[1:1], pkcs12.DefaultPassword)
		if err != nil {
			log.Fatalf("Failed to create PFX: %v", err)
		}

		if err := os.WriteFile("certificate.pfx", pfxData, 0644); err != nil {
			log.Fatalf("Failed to write certificate.pfx: %v", err)
		}

		fmt.Println("PFX file created successfully: certificate.pfx")


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
