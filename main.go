package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

/*
===================================CONFIGURATION FUNCTIONALITY=============================================
*/

// Configuration is a struct designed to hold the applications variable configuration settings
type Configuration struct {
	MongoURI     string
	Database     string
	TokenSecret  string
	RootAdmin    string
	RootPassword string
	RootEmail    string
	RootGroup    string
	Registration string
}

// ConfigurationSettings is a function that reads a json configuration file and outputs a Configuration struct
func ConfigurationSettings() (*Configuration, error) {
	confFile := "confs.json"
	file, _ := os.Open(confFile)
	decoder := json.NewDecoder(file)
	configurationSettings := Configuration{}
	err := decoder.Decode(&configurationSettings)
	if err != nil {
		return &configurationSettings, err
	}
	return &configurationSettings, nil
}

// InitializeEnvironmentalVars initializes the environmental variables for the application
func (c *Configuration) InitializeEnvironmentalVars() {
	os.Setenv("MONGO_URI", c.MongoURI)
	os.Setenv("DATABASE", c.Database)
	os.Setenv("TOKEN_SECRET", c.TokenSecret)
	os.Setenv("ROOT_ADMIN", c.RootAdmin)
	os.Setenv("ROOT_PASSWORD", c.RootPassword)
	os.Setenv("ROOT_EMAIL", c.RootEmail)
	os.Setenv("ROOT_GROUP", c.RootGroup)
	os.Setenv("REGISTRATION", c.Registration)
}

/*
===================================UTILITY FUNCTIONS=============================================
*/

// generateUUID for index keying records of data
func generateUUID() (string, error) {
	curId, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return curId.String(), nil
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

/*
===================================TOKEN FUNCTIONALITY=============================================
*/

// TokenData stores the structured data from a session token for use
type TokenData struct {
	UserId  string
	Role    string
	GroupId string
}

// CreateToken is used to create a new session JWT token
func CreateToken(user *User, exp int64) (string, error) {
	var MySigningKey = []byte(os.Getenv("TOKEN_SECRET"))
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["role"] = user.Role
	claims["username"] = user.Username
	claims["uuid"] = user.Uuid
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
		tokenData.UserId = tokenClaims["uuid"].(string)
		tokenData.Role = tokenClaims["role"].(string)
		tokenData.GroupId = tokenClaims["group_id"].(string)
		return &tokenData, nil
	}
	return &tokenData, errors.New("invalid token")
}

/*
==============================AUTHENTICATION MIDDLEWARE FUNCTIONALITY===========================================
*/

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

/*
===================================ROOT TOKEN BLACKLIST MODEL==========================================
*/

// Blacklist is a root struct that is used to store the json encoded data for/from a mongodb blacklist doc.
type Blacklist struct {
	Id               string `json:"id,omitempty"`
	AuthToken        string `json:"auth_token,omitempty"`
	LastModified     string `json:"last_modified,omitempty"`
	CreationDatetime string `json:"creation_datetime,omitempty"`
}

// addTimeStamps updates a Group struct with a timestamp
func (g *Blacklist) addTimeStamps(newRecord bool) {
	currentTime := time.Now().UTC()
	g.LastModified = currentTime.String()
	if newRecord {
		g.CreationDatetime = currentTime.String()
	}
}

/*
===================================ROOT USER MODEL=============================================
*/

// User is a root struct that is used to store the json encoded data for/from a mongodb user doc.
type User struct {
	Id               string `json:"id,omitempty"`
	Uuid             string `json:"uuid,omitempty"`
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
	FirstName        string `json:"firstname,omitempty"`
	LastName         string `json:"lastname,omitempty"`
	Email            string `json:"email,omitempty"`
	Role             string `json:"role,omitempty"`
	GroupId          string `json:"group_id,omitempty"`
	LastModified     string `json:"last_modified,omitempty"`
	CreationDatetime string `json:"creation_datetime,omitempty"`
}

// BuildUpdate is a function that setups the base user struct during a user modification request
func (g *User) BuildUpdate(curUser *userModel) {
	if len(g.Username) == 0 {
		g.Username = curUser.Username
	}
	if len(g.FirstName) == 0 {
		g.FirstName = curUser.FirstName
	}
	if len(g.LastName) == 0 {
		g.LastName = curUser.LastName
	}
	if len(g.Email) == 0 {
		g.Email = curUser.Email
	}
	if len(g.GroupId) == 0 {
		g.GroupId = curUser.GroupId
	}
	if len(g.Role) == 0 {
		g.Role = curUser.Role
	}
}

// addTimeStamps updates a Group struct with a timestamp
func (g *User) addTimeStamps(newRecord bool) {
	currentTime := time.Now().UTC()
	g.LastModified = currentTime.String()
	if newRecord {
		g.CreationDatetime = currentTime.String()
	}
}

// UserService is an interface used to manage the relevant user doc controllers
type UserService interface {
	AuthenticateUser(u *User) (*User, error)
	BlacklistAuthToken(authToken string)
	RefreshToken(tokenData *TokenData) (*User, error)
	UpdatePassword(tokenData *TokenData, CurrentPassword string, newPassword string) (*User, error)
	UserCreate(u *User) (*User, error)
	UserDelete(u *User) (*User, error)
	UsersFind(u *User) ([]*User, error)
	UserFind(u *User) (*User, error)
	UserUpdate(u *User) (*User, error)
	UserDocInsert(u *User) (*User, error)
}

/*
===================================ROOT GROUP MODEL=============================================
*/

// Group is a root struct that is used to store the json encoded data for/from a mongodb group doc.
type Group struct {
	Id               string `json:"id,omitempty"`
	Uuid             string `json:"uuid,omitempty"`
	GroupType        string `json:"group_type,omitempty"`
	Name             string `json:"name,omitempty"`
	LastModified     string `json:"last_modified,omitempty"`
	CreationDatetime string `json:"creation_datetime,omitempty"`
}

// addTimeStamps updates a Group struct with a timestamp
func (g *Group) addTimeStamps(newRecord bool) {
	currentTime := time.Now().UTC()
	g.LastModified = currentTime.String()
	if newRecord {
		g.CreationDatetime = currentTime.String()
	}
}

// GroupService is an interface used to manage the relevant group doc controllers
type GroupService interface {
	GroupCreate(g *Group) (*Group, error)
	GroupFind(g *Group) (*Group, error)
	GroupsFind() ([]*Group, error)
	GroupDelete(g *Group) (*Group, error)
	GroupUpdate(g *Group) (*Group, error)
	GroupDocInsert(g *Group) (*Group, error)
}

/*
===================================DATABASE FUNCTIONALITY=============================================
*/

// DBClient manages a database connection
type DBClient struct {
	connectionURI string
	client        *mongo.Client
}

// initializeNewClient is a function that takes a mongoUri string and outputs a connected mongo client for the app to use
func initializeNewClient() (*DBClient, error) {
	newDBClient := DBClient{connectionURI: os.Getenv("MONGO_URI")}
	var err error
	newDBClient.client, err = mongo.NewClient(options.Client().ApplyURI(newDBClient.connectionURI))
	return &newDBClient, err
}

// Connect opens a new connection to the database
func (db *DBClient) Connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := db.client.Connect(ctx)
	return err
}

// Close closes an open DB connection
func (db *DBClient) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := db.client.Disconnect(ctx)
	return err
}

// findOne ...
func (db *DBClient) findOne(filter bson.D, collectionName string, dataModel interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := db.client.Database(os.Getenv("DATABASE")).Collection(collectionName).FindOne(ctx, filter).Decode(dataModel)
	if err != nil {
		return errors.New(collectionName + " not found")
	}
	return nil
}

// FindOneUser Function to get a user from datasource with custom filter
func (db *DBClient) FindOneUser(filter bson.D) (*User, error) {
	var model = newUserModel(&User{})
	err := db.findOne(filter, "users", &model)
	return model.toRootUser(), err
}

// FindOneGroup Function to get a user from datasource with custom filter
func (db *DBClient) FindOneGroup(filter bson.D) (*Group, error) {
	var model = newGroupModel(&Group{})
	err := db.findOne(filter, "groups", &model)
	return model.toRootGroup(), err
}

/*
===================================TOKEN BLACKLIST DB MODEL=============================================
*/

type blacklistModel struct {
	Id               primitive.ObjectID `bson:"_id,omitempty"`
	AuthToken        string             `bson:"auth_token,omitempty"`
	LastModified     string             `bson:"last_modified,omitempty"`
	CreationDatetime string             `bson:"creation_datetime,omitempty"`
}

func newBlacklistModel(bl *Blacklist) *blacklistModel {
	return &blacklistModel{
		AuthToken:        bl.AuthToken,
		LastModified:     bl.LastModified,
		CreationDatetime: bl.CreationDatetime,
	}
}

func (bl *blacklistModel) toRootBlacklist() *Blacklist {
	return &Blacklist{
		Id:               bl.Id.Hex(),
		AuthToken:        bl.AuthToken,
		LastModified:     bl.LastModified,
		CreationDatetime: bl.CreationDatetime,
	}
}

/*
===================================USER DB MODEL AND SERVICE=============================================
*/

type userModel struct {
	Id               primitive.ObjectID `bson:"_id,omitempty"`
	Uuid             string             `bson:"uuid,omitempty"`
	Username         string             `bson:"username,omitempty"`
	Password         string             `bson:"password,omitempty"`
	FirstName        string             `bson:"firstname,omitempty"`
	LastName         string             `bson:"lastname,omitempty"`
	Email            string             `bson:"email,omitempty"`
	Role             string             `bson:"role,omitempty"`
	GroupId          string             `bson:"group_id,omitempty"`
	LastModified     string             `bson:"last_modified,omitempty"`
	CreationDatetime string             `bson:"creation_datetime,omitempty"`
}

func newUserModel(u *User) *userModel {
	return &userModel{
		Uuid:             u.Uuid,
		Username:         u.Username,
		Password:         u.Password,
		FirstName:        u.FirstName,
		LastName:         u.LastName,
		Email:            u.Email,
		Role:             u.Role,
		GroupId:          u.GroupId,
		LastModified:     u.LastModified,
		CreationDatetime: u.CreationDatetime,
	}
}

func (u *userModel) toRootUser() *User {
	return &User{
		Id:               u.Id.Hex(),
		Uuid:             u.Uuid,
		Username:         u.Username,
		Password:         u.Password,
		FirstName:        u.FirstName,
		LastName:         u.LastName,
		Email:            u.Email,
		Role:             u.Role,
		GroupId:          u.GroupId,
		LastModified:     u.LastModified,
		CreationDatetime: u.CreationDatetime,
	}
}

// userService is used by the app to manage all user related controllers and functionality
type userService struct {
	collection *mongo.Collection
	db         *DBClient
}

// NewUserService is an exported function used to initialize a new UserService struct
func NewUserService(db *DBClient) *userService {
	collection := db.client.Database(os.Getenv("DATABASE")).Collection("users")
	return &userService{collection, db}
}

// AuthenticateUser is used to authenticate users that are signing in
func (p *userService) AuthenticateUser(user *User) (*User, error) {
	var checkUser = newUserModel(&User{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := p.collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&checkUser)
	if err != nil {
		return user, errors.New("invalid email")
	}
	rootUser := checkUser.toRootUser()
	password := []byte(user.Password)
	checkPassword := []byte(checkUser.Password)
	err = bcrypt.CompareHashAndPassword(checkPassword, password)
	if err == nil {
		return rootUser, nil
	}
	return user, errors.New("invalid password")
}

// BlacklistAuthToken is used during sign-out to add the now invalid auth-token/api key to the blacklist collection
func (p *userService) BlacklistAuthToken(authToken string) {
	var blacklist Blacklist
	blacklist.AuthToken = authToken
	blacklist.addTimeStamps(true)
	blModel := newBlacklistModel(&blacklist)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p.db.client.Database(os.Getenv("DATABASE")).Collection("blacklists").InsertOne(ctx, blModel)
}

// RefreshToken is used to refresh an existing & valid JWT token
func (p *userService) RefreshToken(tokenData *TokenData) (*User, error) {
	if tokenData.UserId == "" {
		return &User{}, errors.New("token missing an userId")
	}
	return p.UserFind(&User{Uuid: tokenData.UserId, GroupId: tokenData.GroupId})
}

// UpdatePassword is used to update the currently logged-in user's password
func (p *userService) UpdatePassword(tokenData *TokenData, CurrentPassword string, newPassword string) (*User, error) {
	var user = newUserModel(&User{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := p.collection.FindOne(ctx, bson.M{"uuid": tokenData.UserId}).Decode(&user)
	if err != nil {
		return &User{}, errors.New("invalid user id")
	}
	// 2. Check current password
	curUser := user.toRootUser()
	password := []byte(CurrentPassword)
	checkPassword := []byte(curUser.Password)
	err = bcrypt.CompareHashAndPassword(checkPassword, password)
	if err == nil {
		// 3. Update doc with new password
		currentTime := time.Now().UTC()
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return curUser, err
		}
		filter := bson.D{{"uuid", curUser.Uuid}}
		update := bson.D{{"$set",
			bson.D{
				{"password", string(hashedPassword)},
				{"last_modified", currentTime.String()},
			},
		}}
		_, err = p.collection.UpdateOne(ctx, filter, update)
		if err != nil {
			return curUser, err
		}
		return curUser, nil
	}
	return &User{}, errors.New("invalid password")
}

// UserCreate is used to create a new user
func (p *userService) UserCreate(user *User) (*User, error) {
	var checkUser = newUserModel(&User{})
	var checkGroup = newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docCount, err := p.collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return user, err
	}
	usernameErr := p.collection.FindOne(ctx, bson.M{"username": user.Username, "group_id": user.GroupId}).Decode(&checkUser)
	emailErr := p.collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&checkUser)
	groupErr := p.db.client.Database(os.Getenv("DATABASE")).Collection("groups").FindOne(ctx, bson.M{"uuid": user.GroupId}).Decode(&checkGroup)
	if usernameErr == nil {
		return &User{}, errors.New("username has been taken")
	} else if emailErr == nil {
		return &User{}, errors.New("email has been taken")
	} else if groupErr != nil {
		return &User{}, errors.New("invalid group id")
	}
	user.Uuid, err = generateUUID()
	if err != nil {
		return user, err
	}
	password := []byte(user.Password)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return user, err
	}
	user.Password = string(hashedPassword)
	if docCount == 0 {
		user.Role = "master_admin"
	} else {
		if user.Role != "master_admin" && user.Role != "group_admin" {
			user.Role = "member"
		} else {
			if user.Role == "master_admin" {
				var masterGroup = newGroupModel(&Group{})
				err = p.db.client.Database(os.Getenv("DATABASE")).Collection("groups").FindOne(ctx, bson.M{"name": os.Getenv("ROOT_GROUP")}).Decode(&masterGroup)
				if groupErr != nil {
					return &User{}, errors.New("root group not found")
				}
				user.GroupId = masterGroup.Uuid
			}
		}
	}
	user.addTimeStamps(true)
	uModel := newUserModel(user)
	p.collection.InsertOne(ctx, uModel)
	return uModel.toRootUser(), nil
}

// UserDelete is used to delete an User
func (p *userService) UserDelete(u *User) (*User, error) {
	var user = newUserModel(&User{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	findFilter := bson.M{"uuid": u.Uuid}
	if u.GroupId != "" {
		findFilter = bson.M{"uuid": u.Uuid, "group_id": u.GroupId}
	}
	//err := p.collection.FindOneAndDelete(ctx, findFilter).Decode(&user)
	currentTime := time.Now().UTC()
	update := bson.D{{"$set",
		bson.D{
			{"deleted_at", currentTime.String()},
		},
	}}
	_, err := p.collection.UpdateOne(ctx, findFilter, update)
	if err != nil {
		return &User{}, err
	}
	return user.toRootUser(), nil
}

// UsersFind is used to find all user docs
func (p *userService) UsersFind(u *User) ([]*User, error) {
	var users []*User
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	findFilter := bson.M{}
	if u.GroupId != "" {
		findFilter = bson.M{"group_id": u.GroupId}
	}
	cursor, err := p.collection.Find(ctx, findFilter)
	if err != nil {
		return users, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var user = newUserModel(&User{})
		cursor.Decode(&user)
		user.Password = ""
		users = append(users, user.toRootUser())
	}
	return users, nil
}

// UserFind is used to find a specific user doc
func (p *userService) UserFind(u *User) (*User, error) {
	var user = newUserModel(&User{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	findFilter := bson.M{"uuid": u.Uuid}
	if u.GroupId != "" {
		findFilter = bson.M{"uuid": u.Uuid, "group_id": u.GroupId}
	}
	err := p.collection.FindOne(ctx, findFilter).Decode(&user)
	if err != nil {
		return &User{}, err
	}
	return user.toRootUser(), nil
}

// UserUpdate is used to update an existing user doc
func (p *userService) UserUpdate(u *User) (*User, error) {
	var curUser = newUserModel(&User{})
	var checkUser = newUserModel(&User{})
	var checkGroup = newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docCount, err := p.collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return &User{}, err
	}
	findFilter := bson.M{"uuid": u.Uuid}
	if u.GroupId != "" {
		findFilter = bson.M{"uuid": u.Uuid, "group_id": u.GroupId}
	}
	err = p.collection.FindOne(ctx, findFilter).Decode(&curUser)
	if err != nil {
		return &User{}, errors.New("user not found")
	}
	u.BuildUpdate(curUser)
	usernameErr := p.collection.FindOne(ctx, bson.M{"username": u.Username, "group_id": u.GroupId}).Decode(&checkUser)
	emailErr := p.collection.FindOne(ctx, bson.M{"email": u.Email}).Decode(&checkUser)
	groupErr := p.db.client.Database(os.Getenv("DATABASE")).Collection("groups").FindOne(ctx, bson.M{"uuid": u.GroupId}).Decode(&checkGroup)
	if usernameErr == nil && curUser.Username != u.Username {
		return &User{}, errors.New("username is taken")
	} else if emailErr == nil && curUser.Email != u.Email {
		return &User{}, errors.New("email is taken")
	} else if groupErr != nil {
		return &User{}, errors.New("invalid group id")
	}
	if docCount == 0 {
		return &User{}, errors.New("no users found")
	}
	filter := bson.D{{"uuid", u.Uuid}}
	currentTime := time.Now().UTC()
	if len(u.Password) != 0 {
		password := []byte(u.Password)
		hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			return &User{}, err
		}
		update := bson.D{{"$set",
			bson.D{
				{"password", string(hashedPassword)},
				{"firstname", u.FirstName},
				{"lastname", u.LastName},
				{"username", u.Username},
				{"email", u.Email},
				{"role", u.Role},
				{"group_id", u.GroupId},
				{"last_modified", currentTime.String()},
			},
		}}
		_, err = p.collection.UpdateOne(ctx, filter, update)
		if err != nil {
			return &User{}, err
		}
		u.Password = ""
		return u, nil
	}
	update := bson.D{{"$set",
		bson.D{
			{"firstname", u.FirstName},
			{"lastname", u.LastName},
			{"username", u.Username},
			{"email", u.Email},
			{"role", u.Role},
			{"group_id", u.GroupId},
			{"last_modified", currentTime.String()},
		},
	}}
	_, err = p.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return &User{}, err
	}
	return u, nil
}

// UserDocInsert is used to insert user doc directly into mongodb for testing purposes
func (p *userService) UserDocInsert(u *User) (*User, error) {
	password := []byte(u.Password)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return u, err
	}
	u.Password = string(hashedPassword)
	var insertUser = newUserModel(u)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = p.collection.InsertOne(ctx, insertUser)
	if err != nil {
		return u, err
	}
	return insertUser.toRootUser(), nil
}

/*
===================================GROUP DB MODEL AND SERVICE=============================================
*/

// groupModel structures a group BSON document to save in a groups collection
type groupModel struct {
	Id               primitive.ObjectID `bson:"_id,omitempty"`
	Uuid             string             `bson:"uuid,omitempty"`
	GroupType        string             `bson:"group_type,omitempty"`
	Name             string             `bson:"name,omitempty"`
	LastModified     string             `bson:"last_modified,omitempty"`
	CreationDatetime string             `bson:"creation_datetime,omitempty"`
}

// newGroupModel initializes a new pointer to a groupModel struct from a pointer to a JSON Group struct
func newGroupModel(g *Group) *groupModel {
	return &groupModel{
		Uuid:             g.Uuid,
		GroupType:        g.GroupType,
		Name:             g.Name,
		LastModified:     g.LastModified,
		CreationDatetime: g.CreationDatetime,
	}
}

// toRootGroup creates and return a new pointer to a Group JSON struct from a pointer to a BSON groupModel
func (g *groupModel) toRootGroup() *Group {
	return &Group{
		Id:               g.Id.Hex(),
		Uuid:             g.Uuid,
		GroupType:        g.GroupType,
		Name:             g.Name,
		LastModified:     g.LastModified,
		CreationDatetime: g.CreationDatetime,
	}
}

// groupService is used by the app to manage all group related controllers and functionality
type groupService struct {
	collection *mongo.Collection
	db         *DBClient
}

// NewGroupService is an exported function used to initialize a new GroupService struct
func NewGroupService(db *DBClient) *groupService {
	collection := db.client.Database(os.Getenv("DATABASE")).Collection("groups")
	return &groupService{collection, db}
}

// GroupCreate is used to create a new user group
func (p *groupService) GroupCreate(group *Group) (*Group, error) {
	if group.Name == "" {
		return group, errors.New("new group must have a Name")
	}
	var checkGroup = newGroupModel(&Group{})
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = p.collection.FindOne(ctx, bson.M{"name": group.Name}).Decode(&checkGroup)
	if err == nil {
		return &Group{}, errors.New("group name exists")
	}
	group.addTimeStamps(true)
	gModel := newGroupModel(group)
	_, err = p.collection.InsertOne(ctx, gModel)
	if err != nil {
		return group, err
	}
	return gModel.toRootGroup(), nil
}

// GroupsFind is used to find all group docs in a MongoDB Collection
func (p *groupService) GroupsFind() ([]*Group, error) {
	var groups []*Group
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cursor, err := p.collection.Find(ctx, bson.M{})
	if err != nil {
		return groups, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var group = newGroupModel(&Group{})
		err = cursor.Decode(&group)
		if err != nil {
			return groups, err
		}
		groups = append(groups, group.toRootGroup())
	}
	return groups, nil
}

// GroupFind is used to find a specific group doc
func (p *groupService) GroupFind(g *Group) (*Group, error) {
	var group = newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := p.collection.FindOne(ctx, bson.M{"uuid": g.Uuid}).Decode(&group)
	if err != nil {
		return &Group{}, err
	}
	return group.toRootGroup(), nil
}

// GroupDelete is used to delete a group doc
func (p *groupService) GroupDelete(g *Group) (*Group, error) {
	var group = newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := p.collection.FindOneAndDelete(ctx, bson.M{"uuid": g.Uuid}).Decode(&group)
	if err != nil {
		return &Group{}, err
	}
	return group.toRootGroup(), nil
}

// GroupUpdate is used to update an existing group
func (p *groupService) GroupUpdate(g *Group) (*Group, error) {
	var curGroup = newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	groupErr := p.collection.FindOne(ctx, bson.M{"uuid": g.Uuid}).Decode(&curGroup)
	if groupErr != nil {
		return &Group{}, errors.New("group not found")
	}
	filter := bson.D{{"uuid", g.Uuid}}
	currentTime := time.Now().UTC()
	update := bson.D{{"$set",
		bson.D{
			{"name", g.Name},
			{"last_modified", currentTime.String()},
		},
	}}
	_, err := p.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return g, err
	}
	return g, nil
}

// GroupDocInsert is used to insert a group doc directly into mongodb for testing purposes
func (p *groupService) GroupDocInsert(g *Group) (*Group, error) {
	var insertGroup = newGroupModel(g)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := p.collection.InsertOne(ctx, insertGroup)
	if err != nil {
		return g, err
	}
	return insertGroup.toRootGroup(), nil
}

/*
===================================USER ROUTER FUNCTIONALITY=============================================
*/

type userRouter struct {
	uService UserService
	gService GroupService
}

// NewUserRouter is a function that initializes a new userRouter struct
func NewUserRouter(router *mux.Router, u UserService, g GroupService, client *DBClient) *mux.Router {
	uRouter := userRouter{u, g}
	router.HandleFunc("/auth", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth", uRouter.Signin).Methods("POST")
	router.HandleFunc("/auth", MemberTokenVerifyMiddleWare(uRouter.RefreshSession, client)).Methods("GET")
	router.HandleFunc("/auth", MemberTokenVerifyMiddleWare(uRouter.Signout, client)).Methods("DELETE")
	router.HandleFunc("/auth/register", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth/register", uRouter.RegisterUser).Methods("POST")
	router.HandleFunc("/auth/api-key", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth/api-key", MemberTokenVerifyMiddleWare(uRouter.GenerateAPIKey, client)).Methods("GET")
	router.HandleFunc("/auth/password", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth/password", MemberTokenVerifyMiddleWare(uRouter.UpdatePassword, client)).Methods("POST")
	router.HandleFunc("/users", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/users", MemberTokenVerifyMiddleWare(uRouter.UsersShow, client)).Methods("GET")
	router.HandleFunc("/users/{userId}", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/users/{userId}", MemberTokenVerifyMiddleWare(uRouter.UserShow, client)).Methods("GET")
	router.HandleFunc("/users", AdminTokenVerifyMiddleWare(uRouter.CreateUser, client)).Methods("POST")
	router.HandleFunc("/users/{userId}", AdminTokenVerifyMiddleWare(uRouter.DeleteUser, client)).Methods("DELETE")
	router.HandleFunc("/users/{userId}", MemberTokenVerifyMiddleWare(uRouter.ModifyUser, client)).Methods("PATCH")
	return router
}

// UpdatePassword is the handler function that manages the user password update process
func (ur *userRouter) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err := r.Body.Close(); err != nil {
		return
	}
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	type passwordStruct struct {
		NewPassword     string `json:"new_password"`
		CurrentPassword string `json:"current_password"`
	}
	var pw passwordStruct
	err = json.Unmarshal(body, &pw)
	if err != nil {
		return
	}
	u, err := ur.uService.UpdatePassword(decodedToken, pw.CurrentPassword, pw.NewPassword)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(403)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusAccepted)
		u.Password = ""
		if err := json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// ModifyUser is the handler function that updates a user
func (ur *userRouter) ModifyUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	var user User
	user.Uuid = userId
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err := r.Body.Close(); err != nil {
		return
	}
	if err := json.Unmarshal(body, &user); err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			return
		}
	}
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	user.GroupId = AdminRouteRoleCheck(decodedToken)
	u, err := ur.uService.UserUpdate(&user)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// Signin is the handler function that manages the user signin process
func (ur *userRouter) Signin(w http.ResponseWriter, r *http.Request) {
	var user User
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err := r.Body.Close(); err != nil {
		return
	}
	if err := json.Unmarshal(body, &user); err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			return
		}
	}
	u, err := ur.uService.AuthenticateUser(&user)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(401)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusUnauthorized, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		expDT := time.Now().Add(time.Hour * 1).Unix()
		sessionToken, err := CreateToken(u, expDT)
		if err != nil {
			return
		}
		w = SetResponseHeaders(w, sessionToken, "")
		w.WriteHeader(http.StatusOK)
		u.Password = ""
		if err := json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// RefreshSession is the handler function that refreshes a users JWT token
func (ur *userRouter) RefreshSession(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	tokenData, err := DecodeJWT(authToken)
	if err != nil {
		return
	}
	user, err := ur.uService.RefreshToken(tokenData)
	if err != nil {
		return
	}
	expDT := time.Now().Add(time.Hour * 1).Unix()
	newToken, err := CreateToken(user, expDT)
	if err != nil {
		return
	}
	w = SetResponseHeaders(w, newToken, "")
	w.WriteHeader(http.StatusOK)
}

// GenerateAPIKey is the handler function that generates 6 month API Key for a given user
func (ur *userRouter) GenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	tokenData, err := DecodeJWT(authToken)
	if err != nil {
		return
	}
	user, err := ur.uService.RefreshToken(tokenData)
	expDT := time.Now().Add(time.Hour * 4380).Unix()
	apiKey, err := CreateToken(user, expDT)
	if err != nil {
		return
	}
	w = SetResponseHeaders(w, "", apiKey)
	w.WriteHeader(http.StatusOK)
	return
}

// Signout is the handler function that ends a users session
func (ur *userRouter) Signout(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	ur.uService.BlacklistAuthToken(authToken)
	w = SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	return
}

// RegisterUser handler function that registers a new user
func (ur *userRouter) RegisterUser(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("REGISTRATION") == "OFF" {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(404)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: 404, Text: "Not Found"}); err != nil {
			return
		}
		return
	} else {
		var user User
		body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
		if err != nil {
			return
		}
		if err := r.Body.Close(); err != nil {
			return
		}
		if err := json.Unmarshal(body, &user); err != nil {
			w = SetResponseHeaders(w, "", "")
			w.WriteHeader(422)
			if err := json.NewEncoder(w).Encode(err); err != nil {
				return
			}
			return
		}
		var group Group
		groupName := user.Username
		groupName += "_group"
		group.Name = groupName
		group.GroupType = "normal"
		group.Uuid, err = generateUUID()
		if err != nil {
			return
		}
		g, err := ur.gService.GroupCreate(&group)
		if err != nil {
			w = SetResponseHeaders(w, "", "")
			w.WriteHeader(403)
			if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
				return
			}
			return
		}
		user.Role = "group_admin"
		user.GroupId = g.Uuid
		u, err := ur.uService.UserCreate(&user)
		if err != nil {
			w = SetResponseHeaders(w, "", "")
			w.WriteHeader(403)
			if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
				return
			}
			return
		} else {
			w = SetResponseHeaders(w, "", "")
			w.WriteHeader(http.StatusCreated)
			u.Password = ""
			if err := json.NewEncoder(w).Encode(u); err != nil {
				return
			}
			return
		}
	}
}

// CreateUser is the handler function that creates a new user
func (ur *userRouter) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user User
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err := r.Body.Close(); err != nil {
		return
	}
	if err := json.Unmarshal(body, &user); err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			return
		}
		return
	}
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupUuid := AdminRouteRoleCheck(decodedToken)
	if groupUuid != "" {
		user.GroupId = groupUuid
	}
	u, err := ur.uService.UserCreate(&user)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(403)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusCreated)
		u.Password = ""
		if err := json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// UsersShow is the handler that shows a specific user
func (ur *userRouter) UsersShow(w http.ResponseWriter, r *http.Request) {
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupUuid := AdminRouteRoleCheck(decodedToken)
	w = SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	users, err := ur.uService.UsersFind(&User{GroupId: groupUuid})
	if err := json.NewEncoder(w).Encode(users); err != nil {
		return
	}
	return
}

// UserShow is the handler that shows all users
func (ur *userRouter) UserShow(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupUuid := AdminRouteRoleCheck(decodedToken)
	user, err := ur.uService.UserFind(&User{Uuid: userId, GroupId: groupUuid})
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusNotFound, Text: err.Error()}); err != nil {
			return
		}
		return
	}
	user.Password = ""
	w = SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		panic(err)
	}
	return
}

// DeleteUser is the handler function that deletes a user
func (ur *userRouter) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupUuid := AdminRouteRoleCheck(decodedToken)
	user, err := ur.uService.UserDelete(&User{Uuid: userId, GroupId: groupUuid})
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusNotFound, Text: err.Error()}); err != nil {
			return
		}
		return
	}
	if user.Uuid != "" {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode("User Deleted"); err != nil {
			return
		}
		return
	}
}

/*
===================================GROUP ROUTER FUNCTIONALITY=============================================
*/

type groupRouter struct {
	gService GroupService
}

// NewGroupRouter is a function that initializes a new groupRouter struct
func NewGroupRouter(router *mux.Router, g GroupService, db *DBClient) *mux.Router {
	gRouter := groupRouter{g}
	router.HandleFunc("/groups", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/groups", AdminTokenVerifyMiddleWare(gRouter.GroupsShow, db)).Methods("GET")
	router.HandleFunc("/groups", AdminTokenVerifyMiddleWare(gRouter.CreateGroup, db)).Methods("POST")
	return router
}

// GroupsShow returns all groups to client
func (gr *groupRouter) GroupsShow(w http.ResponseWriter, r *http.Request) {
	w = SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	groups, err := gr.gService.GroupsFind()
	if err != nil {
		return
	}
	if err := json.NewEncoder(w).Encode(groups); err != nil {
		return
	}
}

// CreateGroup from a REST Request post body
func (gr *groupRouter) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var group Group
	group.GroupType = "normal"
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err = r.Body.Close(); err != nil {
		return
	}
	if err = json.Unmarshal(body, &group); err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err = json.NewEncoder(w).Encode(err); err != nil {
			return
		}
		return
	}
	group.Uuid, err = generateUUID()
	g, err := gr.gService.GroupCreate(&group)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(403)
		if err = json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
	} else {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusCreated)
		if err = json.NewEncoder(w).Encode(g); err != nil {
			return
		}
	}
}

/*
===================================SERVER FUNCTIONALITY=============================================
*/

// Server is a struct that stores the API Apps high level attributes such as the router, config, and services
type Server struct {
	Router       *mux.Router
	UserService  UserService
	GroupService GroupService
}

// NewServer is a function used to initialize a new Server struct
func NewServer(u UserService, g GroupService, db *DBClient) *Server {
	router := mux.NewRouter().StrictSlash(true)
	router = NewGroupRouter(router, g, db)
	router = NewUserRouter(router, u, g, db)
	s := Server{Router: router, UserService: u, GroupService: g}
	return &s
}

// Start starts the initialized server
func (s *Server) Start() {
	log.Println("Listening on port 8080")
	if err := http.ListenAndServe(":8080", handlers.LoggingHandler(os.Stdout, s.Router)); err != nil {
		log.Fatal("http.ListenAndServe: ", err)
	}
}

/*
===================================APP FUNCTIONALITY=============================================
*/

// App is the highest level struct of the rest_api application. Stores the server, client, and config settings.
type App struct {
	server *Server
	client *DBClient
}

// Initialize is a function used to initialize a new instantiation of the API Application
func (a *App) Initialize() error {
	var err error
	// 1) Initialize config settings & set environmental variables
	conf, err := ConfigurationSettings()
	if err != nil {
		return err
	}
	conf.InitializeEnvironmentalVars()
	// 2) Initialize & Connect DB Client
	a.client, err = initializeNewClient()
	if err != nil {
		return err
	}
	err = a.client.Connect()
	if err != nil {
		return err
	}
	// 3) Initial DB Services
	gService := NewGroupService(a.client)
	uService := NewUserService(a.client)
	// 4) Create RootAdmin user if database is empty
	var group Group
	var adminUser User
	group.Name = os.Getenv("ROOT_GROUP")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docCount, _ := a.client.client.Database(os.Getenv("DATABASE")).Collection("groups").CountDocuments(ctx, bson.M{})
	if docCount == 0 {
		group.GroupType = "master_admins"
		group.Uuid, err = generateUUID()
		if err != nil {
			return err
		}
		adminGroup, err := gService.GroupCreate(&group)
		if err != nil {
			return err
		}
		adminUser.Username = os.Getenv("ROOT_ADMIN")
		adminUser.Email = os.Getenv("ROOT_EMAIL")
		adminUser.Password = os.Getenv("ROOT_PASSWORD")
		adminUser.FirstName = "root"
		adminUser.LastName = "admin"
		adminUser.GroupId = adminGroup.Uuid
		_, err = uService.UserCreate(&adminUser)
		if err != nil {
			return err
		}
	}
	// 5) Initialize Server
	a.server = NewServer(uService, gService, a.client)
	return nil
}

// Run is a function used to run a previously initialized API Application
func (a *App) Run() {
	defer a.client.Close()
	a.server.Start()
}

/*
===================================MAIN FUNCTIONALITY=============================================
*/

func main() {
	var app App
	err := app.Initialize()
	if err != nil {
		panic(err)
	}
	app.Run()
}
