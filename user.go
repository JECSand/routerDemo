package main

import (
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"time"
)

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

// bsonFilter
func (g *User) bsonFilter() (bson.D, error) {
	jsonStr, err := json.Marshal(g)
	if err != nil {
		return bson.D{}, err
	}
	return bsonBuildProcess(string(jsonStr)), nil
}

// bsonUpdate
func (g *User) bsonUpdate() (bson.D, error) {
	inner, err := g.bsonFilter()
	if err != nil {
		return bson.D{}, err
	}
	return bson.D{{"$set", inner}}, nil
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
