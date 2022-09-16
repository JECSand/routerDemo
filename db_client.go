package main

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
	"time"
)

// DBClient manages a database connection
type DBClient struct {
	connectionURI string
	client        *mongo.Client
}

// initializeNewClient is a function that takes a mongoUri string and outputs a connected mongo client for the app to use
func initializeNewClient() (*DBClient, error) {
	newDBClient := DBClient{connectionURI: os.Getenv("MONGO_URI")}
	var err error
	newDBClient.client, err = mongo.NewClient(options.Client().ApplyURI(newDBClient.connectionURI))
	return &newDBClient, err
}

// Connect opens a new connection to the database
func (db *DBClient) Connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := db.client.Connect(ctx)
	return err
}

// Close closes an open DB connection
func (db *DBClient) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := db.client.Disconnect(ctx)
	return err
}

// findOne ...
func (db *DBClient) findOne(filter bson.D, collectionName string, dataModel interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := db.client.Database(os.Getenv("DATABASE")).Collection(collectionName).FindOne(ctx, filter).Decode(dataModel)
	if err != nil {
		return errors.New(collectionName + " not found")
	}
	return nil
}

// FindOneUser Function to get a user from datasource with custom filter
func (db *DBClient) FindOneUser(filter bson.D) (*User, error) {
	var model = newUserModel(&User{})
	err := db.findOne(filter, "users", &model)
	return model.toRootUser(), err
}

// FindOneGroup Function to get a user from datasource with custom filter
func (db *DBClient) FindOneGroup(filter bson.D) (*Group, error) {
	var model = newGroupModel(&Group{})
	err := db.findOne(filter, "groups", &model)
	return model.toRootGroup(), err
}
