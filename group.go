package main

import (
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"time"
)

// Group is a root struct that is used to store the json encoded data for/from a mongodb group doc.
type Group struct {
	Id               string `json:"id,omitempty"`
	Uuid             string `json:"uuid,omitempty"`
	GroupType        string `json:"group_type,omitempty"`
	Name             string `json:"name,omitempty"`
	LastModified     string `json:"last_modified,omitempty"`
	CreationDatetime string `json:"creation_datetime,omitempty"`
}

// bsonFilter
func (g *Group) bsonFilter() (bson.D, error) {
	jsonStr, err := json.Marshal(g)
	if err != nil {
		return bson.D{}, err
	}
	return bsonBuildProcess(string(jsonStr)), nil
}

// bsonUpdate
func (g *Group) bsonUpdate() (bson.D, error) {
	inner, err := g.bsonFilter()
	if err != nil {
		return bson.D{}, err
	}
	return bson.D{{"$set", inner}}, nil
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
