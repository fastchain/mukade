package mukadtoperations

import (

	//"git.fintechru.org/masterchain/mstor2.git/fakecrypto"

	"github.com/fastchain/mukade/dbmodels"
	serveroperations "github.com/fastchain/mukade/restapi/operations"
	"strconv"
	"time"

	middleware "github.com/go-openapi/runtime/middleware"
)

/*
GetArchiveLogic is logic to process GET request to dowload archive
*/
func IssueCertificateLogic(Flags MukadeFlags) func(params serveroperations.IssueCertificateParams) middleware.Responder {

	return func(params serveroperations.LineCheckInParams) middleware.Responder {
		token, err := params.HTTPRequest.Cookie("uid")
		if err != nil {
			msg := err.Error()
			return serveroperations.NewLineCheckInInternalServerError().WithPayload(&dbmodels.Error{Message: &msg})
			//panic(err.Error())
		}
		user, err := GetUserByToken(token.Value)
		//residentid,err:= strconv.ParseInt(*params.XAUTH, 10, 32)
		if err != nil {
			msg := err.Error()
			return serveroperations.NewLineCheckInInternalServerError().WithPayload(&dbmodels.Error{Message: &msg})
			//panic(err.Error())
		}

		//checking that line with chekin code exists
		var line dbmodels.Line
		result := dbmodels.DB.First(&line, "checkincode = ?", params.CheckinCode)
		if result.RowsAffected == 0 {
			msg := "Unknown Line"
			return serveroperations.NewLineCheckInInternalServerError().WithPayload(&dbmodels.Error{Message: &msg})
		}

		strLineID := strconv.Itoa(int(*line.Lineid))
		checkintime := time.Now().Unix()
		status := "active"

		//checking that resident  does not exist in line (left line or served  already)
		var resident dbmodels.Resident
		result = dbmodels.DB.Table("line_"+strLineID).First(&resident, "residentid = ?", user.ID)
		if result.RowsAffected == 0 {
			//Adding resident to line
			newresident := &dbmodels.Resident{Residentid: user.ID, Status: &status, Checkintime: &checkintime}
			result = dbmodels.DB.Table("line_" + strLineID).Create(newresident)
			if result.Error != nil {
				msg := result.Error.Error()
				return serveroperations.NewLineCheckInInternalServerError().WithPayload(&dbmodels.Error{Message: &msg})
				//fmt.Println(result.Error.Error())
			}
			//msg:="Unknown Line"
			//return serveroperations.NewLineCheckInInternalServerError().WithPayload(&dbmodels.Error{Message:&msg})
		} else {
			//updating resident if exists
			s := "active"
			resident.Status = &s
			resident.Checkintime = &checkintime
			result = dbmodels.DB.Table("line_"+strLineID).Where("residentid = ?", resident.Residentid).Updates(resident)
			if result.Error != nil {
				//serveroperations.
				//panic(result.Error.Error())
				msg := result.Error.Error()
				return serveroperations.NewLineNextInternalServerError().WithPayload(&dbmodels.Error{Message: &msg})
			}
		}

		//gathering data for response
		//var resident dbmodels.Resident
		result = dbmodels.DB.Table("line_"+strLineID).First(&resident, "residentid = ?", user.ID)
		if result.Error != nil {
			msg := result.Error.Error()
			return serveroperations.NewLineCheckInInternalServerError().WithPayload(&dbmodels.Error{Message: &msg})
			//panic(result.Error.Error())
		}
		resident.Lineid = line.Lineid

		sub, err := GetSubscription(user.ID)
		if err != nil {
			msg := err.Error()
			return serveroperations.NewLineCheckInInternalServerError().WithPayload(&dbmodels.Error{Message: &msg})
			//panic(err.Error())
		}

		err = WebPush(Msg2Bytes(CheckInMsg2), *sub)
		if err != nil {
			msg := err.Error()
			return serveroperations.NewLineCheckInInternalServerError().WithPayload(&dbmodels.Error{Message: &msg})
			//panic(err.Error())
		}

		return serveroperations.NewLineCheckInOK().WithPayload(&resident)
		//.WithPayload(archiveBodyReader)
	}
}
