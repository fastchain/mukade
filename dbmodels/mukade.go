package dbmodels

import (
	"github.com/fastchain/mukade/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"reflect"
)

type Certificate = models.Certificate
type CertificateRequest = models.CertificateRequest

//type Bookings = models.Position
//type User = models.User
//type Error = models.Error

/*
	type Line struct {
		models.Line
	  ID     uint   `json:"id" gorm:"primary_key"`
	  Owner  string `json:"title"`
	  CheckinCode string `json:"title"`
	  //Author string `json:"author"`

}

	type Resident struct {
		ID     uint   `json:"id" gorm:"primary_key"`
		PushToken  uint `json:"pushtoken"`
		Email string `json:"email"`
		//LineId  uint `json:"title"`
		//Author string `json:"author"`
	}

	type Bookings struct {
		//ID     uint   `json:"id" gorm:"primary_key"`
		//LineID  uint `json:"title" gorm:"primary_key"`
		ResidentID  uint `json:"residentid" gorm:"primary_key"`
		CheckinTime uint `json:"checkinTime"`
		CheckoutTime uint `json:"checkoutTime"`
		Status string `json:"status"`
		//Author string `json:"author"`
		table string `gorm:"-"`
	}

	func (p Bookings) TableName() string {
		// double check here, make sure the table does exist!!
		if p.table != "" {
			return p.table
		}
		return "bookings_temp" // default table name
	}

	func CreateBookingTables(name string)  {
		// double check here, make sure the table does exist!!
		DB.Migrator().CreateTable(&Resident{})
		/*
		if result.Error != nil {
			//serveroperations.
			panic(result.Error)
		}


		DB.Migrator().RenameTable(&Resident{}, "line_"+name)

		if result.Error != nil {
			//serveroperations.
			panic(result.Error)
		}

}
*/
func setStructTag(f *reflect.StructField) {
	f.Tag = f.Tag + " gorm:\"primary_key;AUTO_INCREMENT\"" // "`json:name-field`"
	//fmt.Println(f.Tag)
}

var DB *gorm.DB

func ConnectDataBase() {
	dsn := "host=127.0.0.1 user=mukade password=mukade dbname=mukade port=5432 sslmode=disable TimeZone=Asia/Shanghai"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("Failed to connect to database!")
	}

	residents := Certificate{}
	field, ok := reflect.TypeOf(&residents).Elem().FieldByName("Residentid")
	if !ok {
		panic("Field not found")
	}
	setStructTag(&field)

	lines := CertificateRequest{}
	field, ok = reflect.TypeOf(&lines).Elem().FieldByName("Lineid")
	if !ok {
		panic("Field not found")
	}
	setStructTag(&field)

	//users := User{}

	// Creating the table if it doesn't exist
	//db.AutoMigrate(&Bookings{})
	db.AutoMigrate(&residents)
	db.AutoMigrate(&lines)
	//db.AutoMigrate(&users)

	DB = db

}
