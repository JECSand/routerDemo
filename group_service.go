package main

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"os"
	"time"
)

// groupService is used by the app to manage all group related controllers and functionality
type groupService struct {
	collection *mongo.Collection
	db         *DBClient
}

// NewGroupService is an exported function used to initialize a new GroupService struct
func NewGroupService(db *DBClient) *groupService {
	collection := db.client.Database(os.Getenv("DATABASE")).Collection("groups")
	return &groupService{collection, db}
}

// GroupCreate is used to create a new user group
func (p *groupService) GroupCreate(g *Group) (*Group, error) {
	if g.Name == "" {
		return g, errors.New("new group must have a Name")
	}
	checkGroup, err := newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = p.collection.FindOne(ctx, bson.M{"name": g.Name}).Decode(&checkGroup)
	if err == nil {
		return &Group{}, errors.New("group name exists")
	}
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	gm.addTimeStamps(true)
	_, err = p.collection.InsertOne(ctx, gm)
	if err != nil {
		return g, err
	}
	return gm.toRoot(), nil
}

// GroupsFind is used to find all group docs in a MongoDB Collection
func (p *groupService) GroupsFind() ([]*Group, error) {
	var groups []*Group
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cursor, err := p.collection.Find(ctx, bson.M{})
	if err != nil {
		return groups, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		group, err := newGroupModel(&Group{})
		if err != nil {
			return groups, err
		}
		err = cursor.Decode(&group)
		if err != nil {
			return groups, err
		}
		groups = append(groups, group.toRoot())
	}
	return groups, nil
}

// GroupFind is used to find a specific group doc
func (p *groupService) GroupFind(g *Group) (*Group, error) {
	group, err := newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	err = p.collection.FindOne(ctx, bson.M{"_id": gm.Id}).Decode(&group)
	if err != nil {
		return &Group{}, err
	}
	return group.toRoot(), nil
}

// GroupDelete is used to delete a group doc
func (p *groupService) GroupDelete(g *Group) (*Group, error) {
	group, err := newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	err = p.collection.FindOneAndDelete(ctx, bson.M{"_id": gm.Id}).Decode(&group)
	if err != nil {
		return &Group{}, err
	}
	return group.toRoot(), nil
}

// GroupUpdate is used to update an existing group
func (p *groupService) GroupUpdate(g *Group) (*Group, error) {
	curGroup, err := newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	groupErr := p.collection.FindOne(ctx, bson.M{"_id": gm.Id}).Decode(&curGroup)
	if groupErr != nil {
		return &Group{}, errors.New("group not found")
	}
	filter := bson.D{{"_id", gm.Id}}
	currentTime := time.Now().UTC()
	update := bson.D{{"$set",
		bson.D{
			{"name", g.Name},
			{"last_modified", currentTime},
		},
	}}
	_, err = p.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return g, err
	}
	return g, nil
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
