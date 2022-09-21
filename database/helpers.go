package database

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/bsonx"
	"os"
	"time"
)

/*
================ testMongoCursor ==================
*/

// testMongoCollection
type testMongoCursor struct {
	ctx     context.Context
	Results []byte
}

// newTestMongoCursor initiates and returns a testMongoCursor
func newTestMongoCursor(cur *mongo.Cursor) *testMongoCursor {
	return &testMongoCursor{Results: cur.Current}
}

// Next check if there's more result documents to decode
func (c *testMongoCursor) Next(ctx context.Context) bool {
	c.ctx = ctx
	cont := false
	return cont
}

// Decode a result document into the input val
func (c *testMongoCursor) Decode(val interface{}) error {
	fmt.Println(val)
	return nil
}

// Close the test cursor
func (c *testMongoCursor) Close(ctx context.Context) error {
	c.ctx = ctx
	return nil
}

/*
================ testMongoCollection ==================
Extra methods can be added to the DBCollection interface from:
	https://github.com/mongodb/mongo-go-driver/blob/master/mongo/collection.go
as needed
See
	https://github.com/mongodb/mongo-go-driver/blob/947cf7eb5052024ab6c4ef3593d2cfb68f19e89c/x/bsonx/document.go#L48
To expand bson.Doc functionality
*/

// testMongoCollection
type testMongoCollection struct {
	name string
	ctx  context.Context
}

// newTestMongoCollection
func newTestMongoCollection(name string) (*testMongoCollection, error) {
	if name == "" {
		return &testMongoCollection{}, errors.New("invalid test collection name")
	}
	testUserCollection := &testMongoCollection{name: "users"}
	return testUserCollection, nil
}

// InsertOne into test collection
func (coll *testMongoCollection) InsertOne(ctx context.Context, document interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error) {
	testId := ""
	coll.ctx = ctx
	ioOpts := options.MergeInsertOneOptions(opts...)
	imOpts := options.InsertMany()
	fmt.Println(document, ioOpts, imOpts)
	// TODO INSERT ONE
	return &mongo.InsertOneResult{InsertedID: testId}, nil
}

// InsertMany into test collection
func (coll *testMongoCollection) InsertMany(ctx context.Context, documents []interface{}, opts ...*options.InsertManyOptions) (*mongo.InsertManyResult, error) {
	coll.ctx = ctx
	if len(documents) == 0 {
		return nil, mongo.ErrEmptySlice
	}
	fmt.Println(documents, opts)
	// TODO INSERT MANY
	imResult := &mongo.InsertManyResult{InsertedIDs: documents}
	return imResult, mongo.BulkWriteException{}
}

// DeleteOne from test collection
func (coll *testMongoCollection) DeleteOne(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	var delCount int64
	coll.ctx = ctx
	fmt.Println(filter, opts)
	// TODO DELETE
	return &mongo.DeleteResult{DeletedCount: delCount}, nil
}

// FindOneAndDelete finds a document, deletes it from the test collection, and then returns the found document
func (coll *testMongoCollection) FindOneAndDelete(ctx context.Context, filter interface{}, opts ...*options.FindOneAndDeleteOptions) *mongo.SingleResult {
	var rawResult []byte
	coll.ctx = ctx
	fmt.Println(filter, opts)
	// TODO FIND ONE AND DELETE
	doc, err := bsonx.ReadDoc(rawResult)
	res := mongo.NewSingleResultFromDocument(doc, err, nil)
	return res
}

// UpdateOne a document in the test collection
func (coll *testMongoCollection) UpdateOne(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	coll.ctx = ctx
	fmt.Println(filter, update, opts)
	// TODO UPDATE ONE
	return &mongo.UpdateResult{}, nil
}

// UpdateByID a document using an ID as the filter
func (coll *testMongoCollection) UpdateByID(ctx context.Context, id interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	if id == nil {
		return nil, mongo.ErrNilValue
	}
	fmt.Println(id, update, opts)
	// TODO UPDATE BY ID
	return coll.UpdateOne(ctx, bson.D{{"_id", id}}, update, opts...)
}

// Find returns a collection of documents
func (coll *testMongoCollection) Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (cur *mongo.Cursor, err error) {
	var rawResults []byte
	coll.ctx = ctx
	fmt.Println(filter, opts)
	// TODO FIND
	cur = &mongo.Cursor{Current: rawResults}
	return cur, nil
}

// FindOne returns a single test mongo document
func (coll *testMongoCollection) FindOne(ctx context.Context, filter interface{}, opts ...*options.FindOneOptions) *mongo.SingleResult {
	var rawResult []byte
	coll.ctx = ctx
	fmt.Println(filter, opts)
	// TODO FIND ONE
	doc, err := bsonx.ReadDoc(rawResult)
	res := mongo.NewSingleResultFromDocument(doc, err, nil)
	return res
}

// CountDocuments in test mongodb collection
func (coll *testMongoCollection) CountDocuments(ctx context.Context, filter interface{}, opts ...*options.CountOptions) (int64, error) {
	var c int64
	coll.ctx = ctx
	fmt.Println(filter, opts)
	// TODO COUNT
	return c, nil
}

/*
================ testMongoDatabase ==================
*/

// testMongoDatabase
type testMongoDatabase struct {
	ctx             context.Context
	name            string
	testCollections []*testMongoCollection
}

// newTestMongoDatabase
func newTestMongoDatabase(databaseName string) (*testMongoDatabase, error) {
	if databaseName == "" {
		return &testMongoDatabase{}, errors.New("invalid test database name")
	}
	var testsColls []*testMongoCollection
	testUserCollection, err := newTestMongoCollection("users")
	if err != nil {
		return &testMongoDatabase{}, err
	}
	testsColls = append(testsColls, testUserCollection)
	return &testMongoDatabase{
		name:            databaseName,
		testCollections: testsColls,
	}, nil
}

// Collection returns a test collection from the test client
func (c *testMongoDatabase) Collection(dbName string) *testMongoCollection {
	for _, tColl := range c.testCollections {
		if tColl.name == dbName {
			return tColl
		}
	}
	return &testMongoCollection{}
}

/*
================ testMongoClient ==================
*/

// testMongoClient
type testMongoClient struct {
	ctx           context.Context
	connected     bool
	testDatabases []*testMongoDatabase
}

// newTestMongoClient
func newTestMongoClient(connectionURI string) (*testMongoClient, error) {
	if connectionURI == "" {
		return &testMongoClient{}, errors.New("invalid test connection uri")
	}
	var testDBs []*testMongoDatabase
	testMongoDB, err := newTestMongoDatabase("testDB")
	if err != nil {
		return &testMongoClient{}, err
	}
	testDBs = append(testDBs, testMongoDB)
	return &testMongoClient{
		testDatabases: testDBs,
	}, nil
}

// Connect to the in-memory text mongo db
func (c *testMongoClient) Connect(ctx context.Context) error {
	c.ctx = ctx
	if c.connected {
		return errors.New("test mongo client already connected")
	}
	c.connected = true
	return nil
}

// Disconnect from the in-memory text mongo db
func (c *testMongoClient) Disconnect(ctx context.Context) error {
	c.ctx = ctx
	if !c.connected {
		return errors.New("test mongo client not connected")
	}
	c.connected = false
	return nil
}

// Database returns a test database from the test client
func (c *testMongoClient) Database(dbName string) *testMongoDatabase {
	for _, tDB := range c.testDatabases {
		if tDB.name == dbName {
			return tDB
		}
	}
	return &testMongoDatabase{}
}

// Ping the in-memory text mongo db
func (c *testMongoClient) Ping(ctx context.Context, rp *readpref.ReadPref) error {
	c.ctx = ctx
	fmt.Println(rp)
	return nil
}

/*
================ testDBClient ==================
*/

// testDBClient manages a database connection
type testDBClient struct {
	connectionURI string
	client        *testMongoClient
}

// InitializeNewTestClient is a function that takes a mongoUri string and outputs a connected mongo client for the app to use
func initializeNewTestClient() (*testDBClient, error) {
	newDBClient := testDBClient{connectionURI: os.Getenv("MONGO_URI")}
	var err error
	newDBClient.client, err = newTestMongoClient(newDBClient.connectionURI)
	return &newDBClient, err
}

// Connect opens a new connection to the database
func (db *testDBClient) Connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := db.client.Connect(ctx)
	return err
}

// Close closes an open DB connection
func (db *testDBClient) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := db.client.Disconnect(ctx)
	return err
}

// GetCollection returns a mongo collection based on the input collection name
func (db *testDBClient) GetCollection(collectionName string) DBCollection {
	return db.client.Database("test").Collection(collectionName)
}

// NewDBHandler returns a new DBHandler generic interface
func (db *testDBClient) NewDBHandler(collectionName string) *DBHandler[dbModel] {
	col := db.GetCollection(collectionName)
	return &DBHandler[dbModel]{
		db:         db,
		collection: col,
	}
}

// NewUserHandler returns a new DBHandler users interface
func (db *testDBClient) NewUserHandler() *DBHandler[*userModel] {
	col := db.GetCollection("users")
	return &DBHandler[*userModel]{
		db:         db,
		collection: col,
	}
}

// NewGroupHandler returns a new DBHandler groups interface
func (db *testDBClient) NewGroupHandler() *DBHandler[*groupModel] {
	col := db.GetCollection("groups")
	return &DBHandler[*groupModel]{
		db:         db,
		collection: col,
	}
}

// NewBlacklistHandler returns a new DBHandler blacklist interface
func (db *testDBClient) NewBlacklistHandler() *DBHandler[*blacklistModel] {
	col := db.GetCollection("blacklists")
	return &DBHandler[*blacklistModel]{
		db:         db,
		collection: col,
	}
}