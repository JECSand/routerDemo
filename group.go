package main

import "time"

// Group is a root struct that is used to store the json encoded data for/from a mongodb group doc.
type Group struct {
	Id           string    `json:"id,omitempty"`
	Name         string    `json:"name,omitempty"`
	RootAdmin    bool      `json:"root_admin,omitempty"`
	LastModified time.Time `json:"last_modified,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
	DeletedAt    time.Time `json:"deleted_at,omitempty"`
}

// Validate ...
func (g *Group) Validate() (err error) {
	return
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
