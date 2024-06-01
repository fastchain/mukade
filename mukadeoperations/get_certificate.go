package mukadeoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	_ "bytes"
	_ "encoding/json"
	_ "fmt"
	"github.com/fastchain/mukade/dbmodels"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
	_ "io"
	_ "net/http"
)

/*
GetArchiveLogic is logic to process GET request to dowload archive
*/
func GetCertificateLogic(Flags MukadeFlags) func(params serveroperations.GetCertificateParams) middleware.Responder {

	return func(params serveroperations.GetCertificateParams) middleware.Responder {

		//fmt.Println(params.RequestID)
		var crt dbmodels.Certificate
		result := dbmodels.DB.First(&crt, "id = ?", params.CertificateID)
		if result.RowsAffected == 0 {
			//msg:="Line Not found "
			//return serveroperations.NewLineCreateInternalServerError().WithPayload(&dbmodels.Error{Message:&msg})
			panic("Line Not found ")
		}

		return serveroperations.NewGetCertificateOK().WithPayload(&crt)

		//return serveroperations.NewRevokeCertificateOK()
		//return serveroperations.NewLineCheckInOK()
		////.WithPayload(archiveBodyReader)
	}
}
