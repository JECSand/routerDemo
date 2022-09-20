package main

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"os"
	"time"
)

// userService is used by the app to manage all user related controllers and functionality
type userService struct {
	collection *mongo.Collection
	db         *DBClient
	handler    *DBHandler[*userModel]
}

// newUserService is an exported function used to initialize a new UserService struct
func newUserService(db *DBClient, handler *DBHandler[*userModel]) *userService {
	collection := db.client.Database(os.Getenv("DATABASE")).Collection("users")
	return &userService{collection, db, handler}
}

// AuthenticateUser is used to authenticate users that are signing in
func (p *userService) AuthenticateUser(user *User) (*User, error) {
	checkUser, err := newUserModel(&User{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = p.collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&checkUser)
	if err != nil {
		return user, errors.New("invalid email")
	}
	rootUser := checkUser.toRoot()
	password := []byte(user.Password)
	checkPassword := []byte(checkUser.Password)
	err = bcrypt.CompareHashAndPassword(checkPassword, password)
	if err == nil {
		return rootUser, nil
	}
	return user, errors.New("invalid password")
}

// BlacklistAuthToken is used during sign-out to add the now invalid auth-token/api key to the blacklist collection
func (p *userService) BlacklistAuthToken(authToken string) error {
	var blacklist Blacklist
	blacklist.AuthToken = authToken
	blModel, err := newBlacklistModel(&blacklist)
	if err != nil {
		return err
	}
	blModel.addTimeStamps(true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = p.db.client.Database(os.Getenv("DATABASE")).Collection("blacklists").InsertOne(ctx, blModel)
	if err != nil {
		return err
	}
	return nil
}

// RefreshToken is used to refresh an existing & valid JWT token
func (p *userService) RefreshToken(tokenData *TokenData) (*User, error) {
	if tokenData.UserId == "" {
		return &User{}, errors.New("token missing an userId")
	}
	return p.UserFind(&User{Id: tokenData.UserId, GroupId: tokenData.GroupId})
}

// UpdatePassword is used to update the currently logged-in user's password
func (p *userService) UpdatePassword(tokenData *TokenData, currentPassword string, newPassword string) (*User, error) {
	user, err := newUserModel(&User{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = p.collection.FindOne(ctx, bson.M{"_id": tokenData.UserId}).Decode(&user)
	if err != nil {
		return &User{}, errors.New("invalid user id")
	}
	// 2. Check current password
	curUser := user.toRoot()
	password := []byte(currentPassword)
	checkPassword := []byte(curUser.Password)
	err = bcrypt.CompareHashAndPassword(checkPassword, password)
	if err == nil {
		// 3. Update doc with new password
		currentTime := time.Now().UTC()
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return curUser, err
		}
		um, err := newUserModel(curUser)
		if err != nil {
			return curUser, err
		}
		filter := bson.D{{"_id", um.Id}}
		update := bson.D{{"$set",
			bson.D{
				{"password", string(hashedPassword)},
				{"last_modified", currentTime},
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
func (p *userService) UserCreate(u *User) (*User, error) {
	checkUser, err := newUserModel(&User{})
	if err != nil {
		return u, err
	}
	checkGroup, err := newGroupModel(&Group{})
	if err != nil {
		return u, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docCount, err := p.collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return u, err
	}
	um, err := newUserModel(u)
	if err != nil {
		return u, err
	}
	emailErr := p.collection.FindOne(ctx, bson.M{"email": um.Email}).Decode(&checkUser)
	groupErr := p.db.client.Database(os.Getenv("DATABASE")).Collection("groups").FindOne(ctx, bson.M{"_id": um.GroupId}).Decode(&checkGroup)
	if emailErr == nil {
		return &User{}, errors.New("email has been taken")
	} else if groupErr != nil {
		return &User{}, errors.New("invalid group id")
	}
	u.Id = generateObjectID()
	password := []byte(u.Password)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return u, err
	}
	u.Password = string(hashedPassword)
	u.RootAdmin = false
	if docCount == 0 {
		u.Role = "admin"
		u.RootAdmin = true
	} else if u.Role != "admin" {
		u.Role = "member"
	}
	um, err = newUserModel(u)
	if err != nil {
		return u, err
	}
	um.addTimeStamps(true)
	_, err = p.collection.InsertOne(ctx, um)
	if err != nil {
		return u, err
	}
	return um.toRoot(), nil
}

// UserDelete is used to delete an User
func (p *userService) UserDelete(u *User) (*User, error) {
	user, err := newUserModel(&User{})
	if err != nil {
		return u, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	um, err := newUserModel(u)
	if err != nil {
		return u, err
	}
	findFilter := bson.M{"_id": um.Id}
	if u.GroupId != "" {
		findFilter = bson.M{"_id": um.Id, "group_id": um.GroupId}
	}
	err = p.collection.FindOneAndDelete(ctx, findFilter).Decode(&user)
	if err != nil {
		return &User{}, err
	}
	return user.toRoot(), nil
}

// UsersFind is used to find all user docs
func (p *userService) UsersFind(u *User) ([]*User, error) {
	var users []*User
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	um, err := newUserModel(u)
	if err != nil {
		return users, err
	}
	findFilter := bson.M{}
	if u.GroupId != "" {
		findFilter = bson.M{"group_id": um.GroupId}
	}
	cursor, err := p.collection.Find(ctx, findFilter)
	if err != nil {
		return users, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		user, err := newUserModel(&User{})
		if err != nil {
			return users, err
		}
		cursor.Decode(&user)
		user.Password = ""
		users = append(users, user.toRoot())
	}
	return users, nil
}

// UserFind is used to find a specific user doc
func (p *userService) UserFind(u *User) (*User, error) {
	um, err := newUserModel(u)
	if err != nil {
		return u, err
	}
	dm, err := p.handler.FindOne(um)
	if err != nil {
		fmt.Println("CHECK USER ERROR: ", err.Error())
		return &User{}, err
	}
	return dm.toRoot(), nil
}

// UserUpdate is used to update an existing user doc
func (p *userService) UserUpdate(u *User) (*User, error) {
	curUser, err := newUserModel(&User{})
	if err != nil {
		return u, err
	}
	checkUser, err := newUserModel(&User{})
	if err != nil {
		return u, err
	}
	checkGroup, err := newGroupModel(&Group{})
	if err != nil {
		return u, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docCount, err := p.collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return &User{}, err
	}
	um, err := newUserModel(u)
	if err != nil {
		return u, err
	}
	findFilter := bson.M{"_id": um.Id}
	if u.GroupId != "" {
		findFilter = bson.M{"_id": um.Id, "group_id": um.GroupId}
	}
	err = p.collection.FindOne(ctx, findFilter).Decode(&curUser)
	if err != nil {
		return &User{}, errors.New("user not found")
	}
	u.BuildUpdate(curUser)
	emailErr := p.collection.FindOne(ctx, bson.M{"email": um.Email}).Decode(&checkUser)
	groupErr := p.db.client.Database(os.Getenv("DATABASE")).Collection("groups").FindOne(ctx, bson.M{"_id": um.GroupId}).Decode(&checkGroup)
	if emailErr == nil && curUser.Email != u.Email {
		return &User{}, errors.New("email is taken")
	} else if groupErr != nil {
		return &User{}, errors.New("invalid group id")
	}
	if docCount == 0 {
		return &User{}, errors.New("no users found")
	}
	// filter := bson.D{{"_id", um.Id}}
	um, err = newUserModel(u)
	if err != nil {
		return u, err
	}
	if len(u.Password) != 0 {
		password := []byte(u.Password)
		hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		um.Password = string(hashedPassword)
		if err != nil {
			return &User{}, err
		}
	}
	um, err = p.handler.UpdateOne(um)
	if err != nil {
		return &User{}, err
	}
	return um.toRoot(), nil
}

// UserDocInsert is used to insert user doc directly into mongodb for testing purposes
func (p *userService) UserDocInsert(u *User) (*User, error) {
	password := []byte(u.Password)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return u, err
	}
	u.Password = string(hashedPassword)
	insertUser, err := newUserModel(u)
	insertUser.addTimeStamps(true)
	if err != nil {
		return u, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = p.collection.InsertOne(ctx, insertUser)
	if err != nil {
		return u, err
	}
	return insertUser.toRoot(), nil
}
