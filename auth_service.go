package main

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"os"
	"time"
)

// authService is used by the app to manage db auth functionality
type authService struct {
	uService            *userService
	gService            *groupService
	blacklistCollection *mongo.Collection
	db                  *DBClient
	handler             *DBHandler[*blacklistModel]
}

// newAuthService is an exported function used to initialize a new authService struct
func newAuthService(db *DBClient, handler *DBHandler[*blacklistModel], uService *userService, gService *groupService) *authService {
	collection := db.client.Database(os.Getenv("DATABASE")).Collection("blacklists")
	return &authService{uService, gService, collection, db, handler}
}

// checkTokenBlacklist to determine if the submitted Auth-Token or API-Key with what's in the blacklist collection
func (a *authService) checkTokenBlacklist(authToken string) bool {
	var checkToken Blacklist
	collection := a.db.client.Database(os.Getenv("DATABASE")).Collection("blacklists")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	blacklistErr := collection.FindOne(ctx, bson.M{"auth_token": authToken}).Decode(&checkToken)
	if blacklistErr != nil {
		return false
	}
	return true
}

// verifyTokenUser verifies Token's User
func (a *authService) verifyTokenUser(decodedToken *TokenData) (bool, string) {
	tUser := decodedToken.toUser()
	checkUser, err := a.uService.UserFind(tUser)
	if err != nil {
		return false, err.Error()
	}
	checkGroup, err := a.gService.GroupFind(&Group{Id: tUser.GroupId})
	if err != nil {
		return false, err.Error()
	}
	// get User's and User's group docs based on token's user uuid
	if checkUser.GroupId != checkGroup.Id {
		return false, "Incorrect group id"
	}
	return true, "No Error"
}

// tokenVerifyMiddleWare
func (a *authService) tokenVerifyMiddleWare(roleType string, next http.HandlerFunc, w http.ResponseWriter, r *http.Request) {
	var errorObject JWTError
	authToken := r.Header.Get("Auth-Token")
	if a.checkTokenBlacklist(authToken) {
		errorObject.Message = "Invalid Token"
		respondWithError(w, http.StatusUnauthorized, errorObject)
		return
	}
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		errorObject.Message = err.Error()
		respondWithError(w, http.StatusUnauthorized, errorObject)
		return
	}
	verified, verifyMsg := a.verifyTokenUser(decodedToken)
	if verified {
		if roleType == "Admin" && decodedToken.Role == "admin" {
			next.ServeHTTP(w, r)
		} else if roleType != "Admin" {
			next.ServeHTTP(w, r)
		} else {
			errorObject.Message = "Invalid Token"
			respondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	} else {
		errorObject.Message = verifyMsg
		respondWithError(w, http.StatusUnauthorized, errorObject)
		return
	}
}

// AdminTokenVerifyMiddleWare is used to verify that the requester is a valid admin
func (a *authService) AdminTokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.tokenVerifyMiddleWare("Admin", next, w, r)
		return
	}
}

// MemberTokenVerifyMiddleWare is used to verify that a requester is authenticated
func (a *authService) MemberTokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.tokenVerifyMiddleWare("Member", next, w, r)
		return
	}
}
