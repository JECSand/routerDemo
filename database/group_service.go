package database

import (
	"context"
	"errors"
	"routerDemo/models"
	"time"
)

// GroupService is used by the app to manage all group related controllers and functionality
type GroupService struct {
	collection DBCollection
	db         DBClient
	handler    *DBHandler[*groupModel]
}

// NewGroupService is an exported function used to initialize a new GroupService struct
func NewGroupService(db DBClient, handler *DBHandler[*groupModel]) *GroupService {
	collection := db.GetCollection("groups")
	return &GroupService{collection, db, handler}
}

// GroupCreate is used to create a new user group
func (p *GroupService) GroupCreate(g *models.Group) (*models.Group, error) {
	if g.Name == "" {
		return g, errors.New("new group must have a Name")
	}
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	_, err = p.handler.FindOne(gm)
	if err == nil {
		return &models.Group{}, errors.New("group name exists")
	}
	gm, err = p.handler.InsertOne(gm)
	return gm.toRoot(), err
}

// GroupsFind is used to find all group docs in a MongoDB Collection
func (p *GroupService) GroupsFind() ([]*models.Group, error) {
	var groups []*models.Group
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
func (p *GroupService) GroupFind(g *models.Group) (*models.Group, error) {
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	gm, err = p.handler.FindOne(gm)
	return gm.toRoot(), err
}

// GroupDelete is used to delete a group doc
func (p *GroupService) GroupDelete(g *models.Group) (*models.Group, error) {
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	gm, err = p.handler.DeleteOne(gm)
	return gm.toRoot(), err
}

// GroupUpdate is used to update an existing group
func (p *GroupService) GroupUpdate(g *models.Group) (*models.Group, error) {
	gm, err := newGroupModel(g)
	if err != nil {
		return g, err
	}
	_, groupErr := p.handler.FindOne(gm)
	if groupErr != nil {
		return &models.Group{}, errors.New("group not found")
	}
	gm, err = p.handler.UpdateOne(gm)
	return gm.toRoot(), err
}

// GroupDocInsert is used to insert a group doc directly into mongodb for testing purposes
func (p *GroupService) GroupDocInsert(g *models.Group) (*models.Group, error) {
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
