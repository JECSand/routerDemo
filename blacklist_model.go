package main

import (
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type blacklistModel struct {
	Id           primitive.ObjectID `bson:"_id,omitempty"`
	AuthToken    string             `bson:"auth_token,omitempty"`
	LastModified time.Time          `bson:"last_modified,omitempty"`
	CreatedAt    time.Time          `bson:"created_at,omitempty"`
}

// newBlacklistModel initializes a new pointer to a blacklistModel struct from a pointer to a JSON Blacklist struct
func newBlacklistModel(bl *Blacklist) (bm *blacklistModel, err error) {
	bm = &blacklistModel{
		AuthToken:    bl.AuthToken,
		LastModified: bl.LastModified,
		CreatedAt:    bl.CreatedAt,
	}
	if bl.Id != "" {
		bm.Id, err = primitive.ObjectIDFromHex(bl.Id)
	}
	return
}

// addTimeStamps updates a blacklistModel struct with a timestamp
func (b *blacklistModel) addTimeStamps(newRecord bool) {
	currentTime := time.Now().UTC()
	b.LastModified = currentTime
	if newRecord {
		b.CreatedAt = currentTime
	}
}

// toDoc converts the bson blacklistModel into a bson.D
func (b *blacklistModel) toDoc() (doc bson.D, err error) {
	data, err := bson.Marshal(b)
	if err != nil {
		return
	}
	err = bson.Unmarshal(data, &doc)
	return
}

// bsonFilter generates a bson filter for MongoDB queries from the blacklistModel data
func (b *blacklistModel) bsonFilter() (doc bson.D, err error) {
	if b.Id.Hex() != "" {
		doc = bson.D{{"_id", b.Id}}
	}
	return
}

// bsonUpdate generates a bson update for MongoDB queries from the blacklistModel data
func (b *blacklistModel) bsonUpdate() (doc bson.D, err error) {
	inner, err := b.toDoc()
	if err != nil {
		return
	}
	doc = bson.D{{"$set", inner}}
	return
}

// toRoot creates and return a new pointer to a Blacklist JSON struct from a pointer to a BSON blacklistModel
func (b *blacklistModel) toRoot() *Blacklist {
	return &Blacklist{
		Id:           b.Id.Hex(),
		AuthToken:    b.AuthToken,
		LastModified: b.LastModified,
		CreatedAt:    b.CreatedAt,
	}
}
