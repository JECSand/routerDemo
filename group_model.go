package main

import "go.mongodb.org/mongo-driver/bson/primitive"

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
