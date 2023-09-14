package db

import (
	"fmt"

	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var _db *gorm.DB

func ReadDB() {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("%w", err))
	}
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s", viper.GetString("postgres.host"), viper.GetString("postgres.user"), viper.GetString("postgres.password"), viper.GetString("postgres.dbname"), viper.GetString("postgres.port"), viper.GetString("postgres.sslmode"), viper.GetString("postgres.TimeZone"))
	_db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database, error=" + err.Error())
	}

	postgresDB, _ := _db.DB()

	postgresDB.SetMaxOpenConns(100)
	postgresDB.SetMaxIdleConns(20)
}

func GetDB() *gorm.DB {
	return _db
}
