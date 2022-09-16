package main

import "go.mongodb.org/mongo-driver/bson/primitive"

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
