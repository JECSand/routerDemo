package main

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"os"
	"time"
)

// App is the highest level struct of the rest_api application. Stores the server, client, and config settings.
type App struct {
	server *Server
	client *DBClient
}

// Initialize is a function used to initialize a new instantiation of the API Application
func (a *App) Initialize() error {
	var err error
	// 1) Initialize config settings & set environmental variables
	conf, err := ConfigurationSettings()
	if err != nil {
		return err
	}
	conf.InitializeEnvironmentalVars()
	// 2) Initialize & Connect DB Client
	a.client, err = initializeNewClient()
	if err != nil {
		return err
	}
	err = a.client.Connect()
	if err != nil {
		return err
	}
	// 3) Initial DB Services
	gService := NewGroupService(a.client)
	uService := NewUserService(a.client)
	// 4) Create RootAdmin user if database is empty
	var group Group
	var adminUser User
	group.Name = os.Getenv("ROOT_GROUP")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docCount, _ := a.client.client.Database(os.Getenv("DATABASE")).Collection("groups").CountDocuments(ctx, bson.M{})
	if docCount == 0 {
		group.GroupType = "master_admins"
		group.Uuid, err = generateUUID()
		if err != nil {
			return err
		}
		adminGroup, err := gService.GroupCreate(&group)
		if err != nil {
			return err
		}
		adminUser.Username = os.Getenv("ROOT_ADMIN")
		adminUser.Email = os.Getenv("ROOT_EMAIL")
		adminUser.Password = os.Getenv("ROOT_PASSWORD")
		adminUser.FirstName = "root"
		adminUser.LastName = "admin"
		adminUser.GroupId = adminGroup.Uuid
		_, err = uService.UserCreate(&adminUser)
		if err != nil {
			return err
		}
	}
	// 5) Initialize Server
	a.server = NewServer(uService, gService, a.client)
	return nil
}

// Run is a function used to run a previously initialized API Application
func (a *App) Run() {
	defer a.client.Close()
	a.server.Start()
}