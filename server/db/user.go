package db

import (
	"errors"
)

type User struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	UserName string `json:"username"`
	Password string `json:"password,omitempty"`
}

func UserNameIsExist(user_name string) bool {
	db := GetDB()
	result := db.Where("user_name = ?", user_name).First(&User{})
	return result.RowsAffected > 0
}

func AddUser(newusr *User) error {
	if UserNameIsExist(newusr.UserName) {
		return errors.New("the username has been registered")
	}
	db := GetDB()
	if result := db.Create(&newusr); result.Error != nil {
		return result.Error
	}
	return nil
}

func CheckPassword(usr *User) (bool, error) {
	db := GetDB()
	var dbusr User
	result := db.Where("user_name = ?", usr.UserName).First(&dbusr)
	if result.RowsAffected == 0 {
		return false, errors.New("the user_name is not exist")
	}
	if result.Error != nil {
		return false, result.Error
	}
	if usr.Password == dbusr.Password {
		return true, nil
	} else {
		return false, nil
	}
}

func InitUser() {
	db := GetDB()
	db.AutoMigrate(&User{})
}
