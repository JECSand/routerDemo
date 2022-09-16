package main

import "go.mongodb.org/mongo-driver/bson/primitive"

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
