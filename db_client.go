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

// dbModel is an abstraction of the db model types
type dbModel interface {
	bsonFilter() (bson.D, error)
	bsonUpdate() (bson.D, error)
	addTimeStamps(newRecord bool)
}

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

// findOne mongodb doc
func (db *DBClient) findOne(filter bson.D, collectionName string, dataModel interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := db.client.Database(os.Getenv("DATABASE")).Collection(collectionName).FindOne(ctx, filter).Decode(dataModel)
	if err != nil {
		return errors.New(collectionName + " not found")
	}
	return nil
}

// updateOne is used to update a single mongodb doc
func (db *DBClient) updateOne(filter bson.D, update bson.D, collectionName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := db.client.Database(os.Getenv("DATABASE")).Collection(collectionName).UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	return nil
}

// UpdateOne Function to get a user from datasource with custom filter
func (db *DBClient) UpdateOne(filter bson.D, m dbModel, collectionName string) error {
	m.addTimeStamps(false)
	update, err := m.bsonUpdate()
	if err != nil {
		return err
	}
	err = db.updateOne(filter, update, collectionName)
	if err != nil {
		return err
	}
	return err
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
