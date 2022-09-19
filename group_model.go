package main

import (
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

// groupModel structures a group BSON document to save in a groups collection
type groupModel struct {
	Id           primitive.ObjectID `bson:"_id,omitempty"`
	Name         string             `bson:"name,omitempty"`
	RootAdmin    bool               `bson:"root_admin,omitempty"`
	LastModified time.Time          `bson:"last_modified,omitempty"`
	CreatedAt    time.Time          `bson:"created_at,omitempty"`
	DeletedAt    time.Time          `bson:"deleted_at,omitempty"`
}

// newGroupModel initializes a new pointer to a groupModel struct from a pointer to a JSON Group struct
func newGroupModel(g *Group) (gm *groupModel, err error) {
	gm = &groupModel{
		Name:         g.Name,
		RootAdmin:    g.RootAdmin,
		LastModified: g.LastModified,
		CreatedAt:    g.CreatedAt,
		DeletedAt:    g.DeletedAt,
	}
	if g.Id != "" {
		gm.Id, err = primitive.ObjectIDFromHex(g.Id)
	}
	return
}

// addTimeStamps updates a groupModel struct with a timestamp
func (g *groupModel) addTimeStamps(newRecord bool) {
	currentTime := time.Now().UTC()
	g.LastModified = currentTime
	if newRecord {
		g.CreatedAt = currentTime
	}
}

// toDoc converts the bson group model into a bson.D
func (g *groupModel) toDoc() (doc bson.D, err error) {
	data, err := bson.Marshal(g)
	if err != nil {
		return
	}
	err = bson.Unmarshal(data, &doc)
	return
}

// bsonFilter generates a bson filter for MongoDB queries from the groupModel data
func (g *groupModel) bsonFilter() (doc bson.D, err error) {
	if g.Id.Hex() != "" {
		doc = bson.D{{"_id", g.Id}}
	}
	return
}

// bsonUpdate generates a bson update for MongoDB queries from the groupModel data
func (g *groupModel) bsonUpdate() (doc bson.D, err error) {
	inner, err := g.toDoc()
	if err != nil {
		return
	}
	doc = bson.D{{"$set", inner}}
	return
}

// toRoot creates and return a new pointer to a Group JSON struct from a pointer to a BSON groupModel
func (g *groupModel) toRoot() *Group {
	return &Group{
		Id:           g.Id.Hex(),
		Name:         g.Name,
		RootAdmin:    g.RootAdmin,
		LastModified: g.LastModified,
		CreatedAt:    g.CreatedAt,
		DeletedAt:    g.DeletedAt,
	}
}
