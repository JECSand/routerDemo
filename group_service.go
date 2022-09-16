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
func (p *groupService) GroupCreate(group *Group) (*Group, error) {
	if group.Name == "" {
		return group, errors.New("new group must have a Name")
	}
	var checkGroup = newGroupModel(&Group{})
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = p.collection.FindOne(ctx, bson.M{"name": group.Name}).Decode(&checkGroup)
	if err == nil {
		return &Group{}, errors.New("group name exists")
	}
	group.addTimeStamps(true)
	gModel := newGroupModel(group)
	_, err = p.collection.InsertOne(ctx, gModel)
	if err != nil {
		return group, err
	}
	return gModel.toRootGroup(), nil
}

// GroupsFind is used to find all group docs in a MongoDB Collection
func (p *groupService) GroupsFind() ([]*Group, error) {
	var groups []*Group
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cursor, err := p.collection.Find(ctx, bson.M{})
	if err != nil {
		return groups, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var group = newGroupModel(&Group{})
		err = cursor.Decode(&group)
		if err != nil {
			return groups, err
		}
		groups = append(groups, group.toRootGroup())
	}
	return groups, nil
}

// GroupFind is used to find a specific group doc
func (p *groupService) GroupFind(g *Group) (*Group, error) {
	var group = newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := p.collection.FindOne(ctx, bson.M{"uuid": g.Uuid}).Decode(&group)
	if err != nil {
		return &Group{}, err
	}
	return group.toRootGroup(), nil
}

// GroupDelete is used to delete a group doc
func (p *groupService) GroupDelete(g *Group) (*Group, error) {
	var group = newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := p.collection.FindOneAndDelete(ctx, bson.M{"uuid": g.Uuid}).Decode(&group)
	if err != nil {
		return &Group{}, err
	}
	return group.toRootGroup(), nil
}

// GroupUpdate is used to update an existing group
func (p *groupService) GroupUpdate(g *Group) (*Group, error) {
	var curGroup = newGroupModel(&Group{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	groupErr := p.collection.FindOne(ctx, bson.M{"uuid": g.Uuid}).Decode(&curGroup)
	if groupErr != nil {
		return &Group{}, errors.New("group not found")
	}
	filter := bson.D{{"uuid", g.Uuid}}
	currentTime := time.Now().UTC()
	update := bson.D{{"$set",
		bson.D{
			{"name", g.Name},
			{"last_modified", currentTime.String()},
		},
	}}
	_, err := p.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return g, err
	}
	return g, nil
}

// GroupDocInsert is used to insert a group doc directly into mongodb for testing purposes
func (p *groupService) GroupDocInsert(g *Group) (*Group, error) {
	var insertGroup = newGroupModel(g)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := p.collection.InsertOne(ctx, insertGroup)
	if err != nil {
		return g, err
	}
	return insertGroup.toRootGroup(), nil
}
