package main

import (
	"context"
	"encoding/json"
	"github.com/gofrs/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"net/http"
	"os"
	"strings"
	"time"
)

// generateUUID for index keying records of data
func generateUUID() (string, error) {
	curId, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return curId.String(), nil
}

// jsonStrToArray
func jsonStrToArray(jsonString string) []string {
	replacer := strings.NewReplacer("\",\"", "|", "{", "", "}", "", "\"", "")
	newString := replacer.Replace(jsonString)
	return strings.Split(newString, "|")
}

// bsonBuildProcess inputs a json stringed structure and returns a representation bson.D
func bsonBuildProcess(jsonStr string) bson.D {
	var filter bson.D
	if string(jsonStr) != "{}" {
		fieldArray := jsonStrToArray(jsonStr)
		for _, elElement := range fieldArray {
			keys := strings.Split(elElement, ":")
			filter = append(filter, bson.E{Key: keys[0], Value: keys[1]})
		}
	}
	return filter
}

// HandleOptionsRequest handles incoming OPTIONS request
func HandleOptionsRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Auth-Token, API-Key")
	w.Header().Add("Access-Control-Expose-Headers", "Content-Type, Auth-Token, API-Key")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Methods", "GET,DELETE,POST,PATCH")
	w.WriteHeader(http.StatusOK)
}

// SetResponseHeaders sets the response headers being sent back to the client
func SetResponseHeaders(w http.ResponseWriter, authToken string, apiKey string) http.ResponseWriter {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Auth-Token, API-Key")
	w.Header().Add("Access-Control-Expose-Headers", "Content-Type, Auth-Token, API-Key")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Methods", "GET,DELETE,POST,PATCH")
	if authToken != "" {
		w.Header().Add("Auth-Token", authToken)
	}
	if apiKey != "" {
		w.Header().Add("API-Key", apiKey)
	}
	return w
}

// AdminRouteRoleCheck checks admin routes JWT tokens to ensure that a group admin does not break scope
func AdminRouteRoleCheck(decodedToken *TokenData) string {
	groupUuid := ""
	if decodedToken.Role != "master_admin" {
		groupUuid = decodedToken.GroupId
	}
	return groupUuid
}

// jsonErr structures a standard error to return
type jsonErr struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

// checkTokenBlacklist to determine if the submitted Auth-Token or API-Key with what's in the blacklist collection
func checkTokenBlacklist(authToken string, db *DBClient) bool {
	var checkToken Blacklist
	collection := db.client.Database(os.Getenv("DATABASE")).Collection("blacklists")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	blacklistErr := collection.FindOne(ctx, bson.M{"auth_token": authToken}).Decode(&checkToken)
	if blacklistErr != nil {
		return false
	}
	return true
}

// JWTError is a struct that is used to contain a json encoded error message for any JWT related errors
type JWTError struct {
	Message string `json:"message"`
}

// Return JSON Error to Requested is Auth is bad
func respondWithError(w http.ResponseWriter, status int, error JWTError) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Auth-Token")
	w.Header().Add("Access-Control-Expose-Headers", "Content-Type, Auth-Token")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(error); err != nil {
		panic(err)
	}
}

// returnInitialCheckErrMsg
func returnInitialCheckErrMsg(userErr string, groupErr string, s1 string, s2 string) string {
	errMsg := "Error: "
	if userErr == "NotFound" && groupErr == "NotFound" {
		errMsg += "Invalid " + s1 + " and Invalid " + s2
	} else if userErr == "NotFound" {
		errMsg += "Invalid " + s1
	} else if groupErr == "NotFound" {
		errMsg += "Invalid " + s2
	}
	return errMsg
}

// verifyTokenUser verify Token User
func verifyTokenUser(decodedToken *TokenData, db *DBClient) (bool, string) {
	checkUser, err := db.FindOneUser(bson.D{{"uuid", decodedToken.UserId}})
	if err != nil {
		return false, err.Error()
	}
	checkGroup, err := db.FindOneGroup(bson.D{{"uuid", decodedToken.GroupId}})
	if err != nil {
		return false, err.Error()
	}
	if checkUser.Username == "NotFound" || checkGroup.Name == "NotFound" {
		return false, returnInitialCheckErrMsg(checkUser.Username, checkGroup.Name, "User", "group")
	}
	// get User's and User's group docs based on token's user uuid
	if checkUser.GroupId != decodedToken.GroupId {
		return false, "Incorrect group Uuid"
	}
	return true, "No Error"
}

// tokenVerifyMiddleWare
func tokenVerifyMiddleWare(roleType string, next http.HandlerFunc, db *DBClient, w http.ResponseWriter, r *http.Request) {
	var errorObject JWTError
	authToken := r.Header.Get("Auth-Token")
	if checkTokenBlacklist(authToken, db) {
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
	verified, verifyMsg := verifyTokenUser(decodedToken, db)
	if verified {
		if roleType == "Admin" && decodedToken.Role == "master_admin" {
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
func AdminTokenVerifyMiddleWare(next http.HandlerFunc, db *DBClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenVerifyMiddleWare("Admin", next, db, w, r)
		return
	}
}

// MemberTokenVerifyMiddleWare is used to verify that a requester is authenticated
func MemberTokenVerifyMiddleWare(next http.HandlerFunc, db *DBClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenVerifyMiddleWare("Member", next, db, w, r)
		return
	}
}
