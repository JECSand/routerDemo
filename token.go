package main

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"os"
)

// TokenData stores the structured data from a session token for use
type TokenData struct {
	UserId    string
	Role      string
	RootAdmin bool
	GroupId   string
}

// toUser creates a new User struct using the TokenData and returns a pointer to it
func (t *TokenData) toUser() *User {
	return &User{
		Id:        t.UserId,
		Role:      t.Role,
		RootAdmin: t.RootAdmin,
		GroupId:   t.GroupId,
	}
}

// CreateToken is used to create a new session JWT token
func CreateToken(user *User, exp int64) (string, error) {
	var MySigningKey = []byte(os.Getenv("TOKEN_SECRET"))
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.Id
	claims["role"] = user.Role
	claims["root"] = user.RootAdmin
	claims["group_id"] = user.GroupId
	claims["exp"] = exp
	return token.SignedString(MySigningKey)
}

// DecodeJWT is used to decode a JWT token
func DecodeJWT(curToken string) (*TokenData, error) {
	var tokenData TokenData
	if curToken == "" {
		return &tokenData, errors.New("unauthorized")
	}
	var MySigningKey = []byte(os.Getenv("TOKEN_SECRET"))
	// Decode token
	token, err := jwt.Parse(curToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("error")
		}
		return []byte(MySigningKey), nil
	})
	if err != nil {
		return &tokenData, err
	}
	// Determine user based on token
	if token.Valid {
		tokenClaims := token.Claims.(jwt.MapClaims)
		tokenData.UserId = tokenClaims["id"].(string)
		tokenData.Role = tokenClaims["role"].(string)
		tokenData.RootAdmin = tokenClaims["root"].(bool)
		tokenData.GroupId = tokenClaims["group_id"].(string)
		return &tokenData, nil
	}
	return &tokenData, errors.New("invalid token")
}
