package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

var jwtsecret = []byte("goodbonegamelmaao23413251!")

var db *gorm.DB

func generateUserJWT(user User) (tokenString string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user.Username,
		"exp":  time.Now().Add(time.Minute * 3).Unix(),
	})

	tokenString, err = token.SignedString(jwtsecret)
	return tokenString, err
}

func includeAuth(endpoint func(w http.ResponseWriter, r *http.Request, token *jwt.Token)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("Authorization")
		if reqToken != "" {

			splitToken := strings.Split(reqToken, "Bearer ")

			if len(reqToken) < 2 {
				json.NewEncoder(w).Encode(ErrResponse{
					Err: "authorization invalid",
				})
				return
			}

			reqToken = splitToken[1]

			fmt.Println(reqToken)

			token, err := jwt.Parse(reqToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("failed to validate jwt")
				}
				return jwtsecret, nil
			})

			if err != nil {
				json.NewEncoder(w).Encode(ErrResponse{
					Err: "invalid jwt",
				})
				return
			}

			if !token.Valid {
				json.NewEncoder(w).Encode(ErrResponse{
					Err: "not authorized",
				})
				return
			}

			endpoint(w, r, token)
		} else {
			json.NewEncoder(w).Encode(ErrResponse{
				Err: "no authorization included",
			})
			return
		}
	})
}

func register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(r.Body)
	var t RegisterRequest
	err := decoder.Decode(&t)
	if err != nil {
		json.NewEncoder(w).Encode(ErrResponse{
			Err: "failed to parse request",
		})
		return
	}

	user := User{
		Username:       t.Username,
		Password:       t.Password,
		Email:          t.Email,
		Deaths:         0,
		KD:             0,
		Kills:          0,
		Losses:         0,
		Model:          0,
		MostPlayedGame: "None yet!",
		Wins:           0,
	}

	err = db.Model(&User{}).Create(user).Error

	if err != nil {
		sqlerr, ok := err.(*mysql.MySQLError)
		if !ok {
			fmt.Println(err)
			json.NewEncoder(w).Encode(ErrResponse{
				Err: "error creating user",
			})
		} else {
			if sqlerr.Number == 1062 {
				json.NewEncoder(w).Encode(ErrResponse{
					Err: "username or email already taken",
				})
			}
		}
		return
	}

	token, err := generateUserJWT(user)
	if err != nil {
		fmt.Println(err)
		json.NewEncoder(w).Encode(ErrResponse{
			Err: "failed to generate auth token",
		})
		return
	}

	json.NewEncoder(w).Encode(LoginResponse{
		Jwt: token,
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(r.Body)
	var t LoginRequest
	err := decoder.Decode(&t)
	if err != nil {
		json.NewEncoder(w).Encode(ErrResponse{
			Err: "failed to parse request",
		})
		return
	}

	var user User
	err = db.Model(&User{}).Where(&User{
		Username: t.Username,
	}).First(&user).Error

	if err != nil {
		json.NewEncoder(w).Encode(ErrResponse{
			Err: "failed to login - invalid username",
		})
		return
	}

	if user.Password != t.Password {
		json.NewEncoder(w).Encode(ErrResponse{
			Err: "failed to login - invalid password",
		})
		return
	}

	/*if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(t.Password)) != nil {
		json.NewEncoder(w).Encode(ErrResponse{
			Err: "failed to login - invalid password",
		})
		return
	}*/

	token, err := generateUserJWT(user)
	if err != nil {
		json.NewEncoder(w).Encode(ErrResponse{
			Err: "failed to generate auth token",
		})
		return
	}

	json.NewEncoder(w).Encode(LoginResponse{
		Jwt: token,
	})
}

func getUsers(w http.ResponseWriter, r *http.Request, token *jwt.Token) {

	var users []User
	err := db.Model(&User{}).Find(&users).Error
	if err == nil {
		json.NewEncoder(w).Encode(users)
	}
	return
}

func main() {
	var err error
	db, err = gorm.Open("mysql", "sfsuser:sfsuser@tcp(130.211.220.11)/sfs")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	db.AutoMigrate(&User{})

	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.Handle("/getuser", includeAuth(getUsers))

	http.ListenAndServe(":8069", nil)
	fmt.Println("Listening on port :8069")
}
