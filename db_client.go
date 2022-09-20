package main

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
	"time"
)

// dbModel is an abstraction of the db model types
type dbModel interface {
	toDoc() (doc bson.D, err error)
	bsonFilter() (doc bson.D, err error)
	bsonUpdate() (doc bson.D, err error)
	addTimeStamps(newRecord bool)
	addObjectID()
	postProcess() (err error)
}

// DBHandler is a Generic type struct for organizing dbModel methods
type DBHandler[T dbModel] struct {
	db         *DBClient
	collection *mongo.Collection
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

// NewDBHandler returns a new DBHandler generic interface
func (db *DBClient) NewDBHandler(collectionName string) *DBHandler[dbModel] {
	col := db.client.Database(os.Getenv("DATABASE")).Collection(collectionName)
	return &DBHandler[dbModel]{
		db:         db,
		collection: col,
	}
}

// NewUserHandler returns a new DBHandler users interface
func (db *DBClient) NewUserHandler() *DBHandler[*userModel] {
	col := db.client.Database(os.Getenv("DATABASE")).Collection("users")
	return &DBHandler[*userModel]{
		db:         db,
		collection: col,
	}
}

// NewGroupHandler returns a new DBHandler groups interface
func (db *DBClient) NewGroupHandler() *DBHandler[*groupModel] {
	col := db.client.Database(os.Getenv("DATABASE")).Collection("groups")
	return &DBHandler[*groupModel]{
		db:         db,
		collection: col,
	}
}

// NewBlacklistHandler returns a new DBHandler blacklist interface
func (db *DBClient) NewBlacklistHandler() *DBHandler[*blacklistModel] {
	col := db.client.Database(os.Getenv("DATABASE")).Collection("blacklists")
	return &DBHandler[*blacklistModel]{
		db:         db,
		collection: col,
	}
}

// FindOne is used to get a dbModel from the db with custom filter
func (h *DBHandler[T]) FindOne(filter T) (T, error) {
	var m T
	f, err := filter.bsonFilter()
	if err != nil {
		return filter, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = h.collection.FindOne(ctx, f).Decode(&m)
	if err != nil {
		return filter, err
	}
	return m, nil
}

// FindMany is used to get a slice of dbModels from the db with custom filter
func (h *DBHandler[T]) FindMany(filter T) ([]T, error) {
	var m []T
	f, err := filter.bsonFilter()
	if err != nil {
		return m, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cursor *mongo.Cursor
	if len(f) > 0 {
		cursor, err = h.collection.Find(ctx, f)
	} else {
		cursor, err = h.collection.Find(ctx, bson.M{})
	}
	if err != nil {
		return m, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var md T
		cursor.Decode(&md)
		err = md.postProcess()
		if err != nil {
			return m, err
		}
		m = append(m, md)
	}
	return m, nil
}

// UpdateOne Function to update a dbModel from datasource with custom filter and update model
func (h *DBHandler[T]) UpdateOne(m T) (T, error) {
	f, err := m.bsonFilter()
	if err != nil {
		return m, err
	}
	m.addTimeStamps(false)
	update, err := m.bsonUpdate()
	if err != nil {
		return m, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = h.collection.UpdateOne(ctx, f, update)
	if err != nil {
		return m, err
	}
	err = m.postProcess()
	return m, err
}

// InsertOne adds a new dbModel record to a collection
func (h *DBHandler[T]) InsertOne(m T) (T, error) {
	m.addTimeStamps(true)
	m.addObjectID()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := h.collection.InsertOne(ctx, m)
	if err != nil {
		return m, err
	}
	err = m.postProcess()
	return m, err
}

// DeleteOne adds a new dbModel record to a collection
func (h *DBHandler[T]) DeleteOne(filter T) (T, error) { //TODO: to be replaced with "soft delete"
	var m T
	f, err := filter.bsonFilter()
	if err != nil {
		return m, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = h.collection.FindOneAndDelete(ctx, f).Decode(&m)
	return m, err
}
