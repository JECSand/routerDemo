package main

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/mongo"
	"os"
	"time"
)

// groupService is used by the app to manage all group related controllers and functionality
type groupService struct {
	collection *mongo.Collection
	db         *DBClient
	handler    *DBHandler[*groupModel]
}

// newGroupService is an exported function used to initialize a new GroupService struct
func newGroupService(db *DBClient, handler *DBHandler[*groupModel]) *groupService {
	collection := db.client.Database(os.Getenv("DATABASE")).Collection("groups")
	return &groupService{collection, db, handler}
}

// GroupCreate is used to create a new user group
func (p *groupService) GroupCreate(g *Group) (*Group, error) {
	if g.Name == "" {
		return g, errors.New("new group must have a Name")
	}
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	_, err = p.handler.FindOne(gm)
	if err == nil {
		return &Group{}, errors.New("group name exists")
	}
	gm, err = p.handler.InsertOne(gm)
	return gm.toRoot(), err
}

// GroupsFind is used to find all group docs in a MongoDB Collection
func (p *groupService) GroupsFind() ([]*Group, error) {
	var groups []*Group
	gms, err := p.handler.FindMany(&groupModel{})
	if err != nil {
		return groups, err
	}
	for _, gm := range gms {
		groups = append(groups, gm.toRoot())
	}
	return groups, nil
}

// GroupFind is used to find a specific group doc
func (p *groupService) GroupFind(g *Group) (*Group, error) {
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	gm, err = p.handler.FindOne(gm)
	return gm.toRoot(), err
}

// GroupDelete is used to delete a group doc
func (p *groupService) GroupDelete(g *Group) (*Group, error) {
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	gm, err = p.handler.DeleteOne(gm)
	return gm.toRoot(), err
}

// GroupUpdate is used to update an existing group
func (p *groupService) GroupUpdate(g *Group) (*Group, error) {
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	_, groupErr := p.handler.FindOne(gm)
	if groupErr != nil {
		return &Group{}, errors.New("group not found")
	}
	gm, err = p.handler.UpdateOne(gm)
	return gm.toRoot(), err
}

// GroupDocInsert is used to insert a group doc directly into mongodb for testing purposes
func (p *groupService) GroupDocInsert(g *Group) (*Group, error) {
	insertGroup, err := newGroupModel(g)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	insertGroup.addTimeStamps(true)
	_, err = p.collection.InsertOne(ctx, insertGroup)
	if err != nil {
		return g, err
	}
	return insertGroup.toRoot(), nil
}
