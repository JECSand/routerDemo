package database

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"os"
	"routerDemo/auth"
	"routerDemo/models"
	"routerDemo/utilities"
	"time"
)

// UserService is used by the app to manage all user related controllers and functionality
type UserService struct {
	collection   *mongo.Collection
	db           *DBClient
	userHandler  *DBHandler[*userModel]
	groupHandler *DBHandler[*groupModel]
}

// NewUserService is an exported function used to initialize a new UserService struct
func NewUserService(db *DBClient, uHandler *DBHandler[*userModel], gHandler *DBHandler[*groupModel]) *UserService {
	collection := db.Client.Database(os.Getenv("DATABASE")).Collection("users")
	return &UserService{collection, db, uHandler, gHandler}
}

// AuthenticateUser is used to authenticate users that are signing in
func (p *UserService) AuthenticateUser(u *models.User) (*models.User, error) {
	um, err := newUserModel(u)
	if err != nil {
		return u, err
	}
	checkUser, err := p.userHandler.FindOne(um)
	if err != nil {
		return &models.User{}, errors.New("invalid email")
	}
	rootUser := checkUser.toRoot()
	password := []byte(u.Password)
	checkPassword := []byte(checkUser.Password)
	err = bcrypt.CompareHashAndPassword(checkPassword, password)
	if err == nil {
		return rootUser, nil
	}
	return u, errors.New("invalid password")
}

// UserCreate is used to create a new user
func (p *UserService) UserCreate(u *models.User) (*models.User, error) {
	um, err := newUserModel(u)
	if err != nil {
		return u, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docCount, err := p.collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return u, err
	}
	_, emailErr := p.userHandler.FindOne(&userModel{Email: um.Email})
	_, groupErr := p.groupHandler.FindOne(&groupModel{Id: um.GroupId})
	if emailErr == nil {
		return &models.User{}, errors.New("email has been taken")
	} else if groupErr != nil {
		return &models.User{}, errors.New("invalid group id")
	}
	u.Id = utilities.GenerateObjectID()
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
	um, err = p.userHandler.InsertOne(um)
	return um.toRoot(), err
}

// UserDelete is used to delete an User
func (p *UserService) UserDelete(u *models.User) (*models.User, error) {
	um, err := newUserModel(u)
	if err != nil {
		return u, err
	}
	um, err = p.userHandler.DeleteOne(um)
	return um.toRoot(), err
}

// UsersFind is used to find all user docs
func (p *UserService) UsersFind(u *models.User) ([]*models.User, error) {
	var users []*models.User
	um, err := newUserModel(u)
	if err != nil {
		return users, err
	}
	ums, err := p.userHandler.FindMany(um)
	if err != nil {
		return users, err
	}
	for _, m := range ums {
		users = append(users, m.toRoot())
	}
	return users, nil
}

// UserFind is used to find a specific user doc
func (p *UserService) UserFind(u *models.User) (*models.User, error) {
	um, err := newUserModel(u)
	if err != nil {
		return u, err
	}
	um, err = p.userHandler.FindOne(um)
	return um.toRoot(), err
}

// UserUpdate is used to update an existing user doc
func (p *UserService) UserUpdate(u *models.User) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docCount, err := p.collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return &models.User{}, err
	}
	if docCount == 0 {
		return &models.User{}, errors.New("no users found")
	}
	um, err := newUserModel(u)
	if err != nil {
		return u, err
	}
	curUser, err := p.userHandler.FindOne(um)
	if err != nil {
		return u, err
	}
	u.BuildUpdate(curUser.toRoot())
	_, emailErr := p.userHandler.FindOne(&userModel{Email: um.Email})
	_, groupErr := p.groupHandler.FindOne(&groupModel{Id: um.GroupId})
	if emailErr == nil && curUser.Email != u.Email {
		return &models.User{}, errors.New("email is taken")
	} else if groupErr != nil {
		return &models.User{}, errors.New("invalid group id")
	}
	um, err = newUserModel(u)
	if err != nil {
		return u, err
	}
	if len(u.Password) != 0 {
		password := []byte(u.Password)
		hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		um.Password = string(hashedPassword)
		if err != nil {
			return &models.User{}, err
		}
	}
	um, err = p.userHandler.UpdateOne(um)
	return um.toRoot(), err
}

// UpdatePassword is used to update the currently logged-in user's password
func (p *UserService) UpdatePassword(tokenData *auth.TokenData, currentPassword string, newPassword string) (*models.User, error) {
	um, err := newUserModel(tokenData.ToUser())
	if err != nil {
		return &models.User{}, err
	}
	user, err := p.userHandler.FindOne(um)
	if err != nil {
		return &models.User{}, err
	}
	// 2. Check current password
	password := []byte(currentPassword)
	checkPassword := []byte(user.Password)
	err = bcrypt.CompareHashAndPassword(checkPassword, password)
	if err == nil { // 3. Update doc with new password
		currentTime := time.Now().UTC()
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return &models.User{}, err
		}
		filter := bson.D{{"_id", user.Id}}
		update := bson.D{{"$set",
			bson.D{
				{"password", string(hashedPassword)},
				{"last_modified", currentTime},
			},
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err = p.collection.UpdateOne(ctx, filter, update)
		if err != nil {
			return &models.User{}, err
		}
		user.Password = ""
		return user.toRoot(), nil
	}
	return &models.User{}, errors.New("invalid password")
}

// UserDocInsert is used to insert user doc directly into mongodb for testing purposes
func (p *UserService) UserDocInsert(u *models.User) (*models.User, error) {
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
