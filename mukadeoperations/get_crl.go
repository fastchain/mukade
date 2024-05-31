package mukadeoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/cfssl/api"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
	"io"
	"net/http"
)

/*
GetArchiveLogic is logic to process GET request to dowload archive
*/

type BufferCloser struct {
	*bytes.Buffer
}

func (bc *BufferCloser) Close() error {
	return nil
}

func RequestCRLLogic(Flags MukadeFlags) func(params serveroperations.RequestCRLParams) middleware.Responder {

	return func(params serveroperations.RequestCRLParams) middleware.Responder {

		resp, err := http.Get("http://127.0.0.1:8888/api/v1/cfssl/crl")
		if err != nil {
			panic(err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		//fmt.Println(string(body))

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

		message := new(api.Response)
		err = json.Unmarshal(body, message)
		if err != nil {
			panic(err)
		}

		der, err := base64.StdEncoding.DecodeString(fmt.Sprint(message.Result))
		if err != nil {
			panic(err)
		}

		fmt.Println(der)

		//var jjj string
		//jjj = fmt.Sprint(body)

		//buf := &bytes.Buffer{}
		//buf.Write(der)
		//buf.WriteString("Hello")

		//reader := bytes.NewReader(der)
		//readCloser := io.NopCloser(reader)
		////rsp := models.CRL{Raw: readCloser}
		//
		//var w middleware.Responder
		//
		//var z http.ResponseWriter
		//kkz := w.WriteResponse(z)
		//if _, err := w.WriteResponse.Write(der); err != nil {
		//	// If there is an error writing the response, return a 500 error
		//	return NewDownloadFileInternalServerError().WithPayload("Error writing response")
		//}

		//out := io.ReadWriteCloser(buf)

		buffer := bytes.NewBuffer(der)
		buf := &BufferCloser{Buffer: buffer}
		fmt.Println(buf)

		reader := bytes.NewReader(der)

		// Step 2: Convert io.Reader to io.ReadCloser using ioutil.NopCloser
		readCloser := io.NopCloser(reader)

		//return serveroperations.NewRequestCRLOK().WithPayload(io.ReadWriteCloser(buf))
		ret := serveroperations.NewRequestCRLOK()
		ret.SetPayload(readCloser)
		return ret
		////.WithPayload(archiveBodyReader)
	}
}
