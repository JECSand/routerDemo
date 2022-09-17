package main

import (
	"context"
	"errors"
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
	err := p.collection.FindOneAndDelete(ctx, findFilter).Decode(&user)
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
	if len(u.Password) != 0 {
		password := []byte(u.Password)
		hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		u.Password = string(hashedPassword)
		if err != nil {
			return &User{}, err
		}
		err = p.db.UpdateOne(filter, u, "users")
		if err != nil {
			return &User{}, err
		}
		u.Password = ""
		return u, nil
	}
	err = p.db.UpdateOne(filter, u, "users")
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
