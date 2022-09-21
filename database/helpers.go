package database

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/bsonx"
	"os"
	"time"
)

/*
================ testCursorData ==================
*/

// testCursorData
type testCursorData struct {
	Results []dbModel `bson:"results,omitempty"`
}

// initTestCursorData instantiates a new testCursorData
func initTestCursorData(res []dbModel) *testCursorData {
	return &testCursorData{Results: res}
}

// toDoc converts the bson testCursorData into a bson.D
func (b *testCursorData) toDoc() (doc bson.D, err error) {
	data, err := bson.Marshal(b)
	if err != nil {
		return
	}
	err = bson.Unmarshal(data, &doc)
	return
}

/*
================ testMongoCursor ==================
*/

// testMongoCollection
type testMongoCursor struct {
	ctx      context.Context
	Results  []byte
	docs     []dbModel
	curCurse int
}

// newTestMongoCursor initiates and returns a testMongoCursor
func newTestMongoCursor(cur *mongo.Cursor) *testMongoCursor {
	var cd testCursorData
	data, err := bsonMarshall(cur.Current)
	if err != nil {
		panic(err)
	}
	err = bson.Unmarshal(data, &cd)
	if err != nil {
		panic(err)
	}
	return &testMongoCursor{Results: cur.Current, docs: cd.Results, curCurse: 0}
}

// Next check if there's more result documents to decode
func (c *testMongoCursor) Next(ctx context.Context) bool {
	c.ctx = ctx
	if c.curCurse < len(c.docs) {
		return true
	}
	return false
}

// Decode a result document into the input val
func (c *testMongoCursor) Decode(val interface{}) error {
	if c.curCurse >= len(c.docs) {
		return errors.New("test cursor out of range")
	}
	curDoc := c.docs[c.curCurse]
	val = curDoc
	c.curCurse++
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

// standardizeID ensures that a dbModels unique identified is returned as a string
func standardizeID(dbDoc dbModel) (string, error) {
	var docId string
	switch t := dbDoc.getID().(type) {
	case nil:
		return docId, errors.New("a test record being inserted is missing a unique identifier")
	case primitive.ObjectID:
		docId = t.Hex()
	case string:
		docId = t
	}
	return docId, nil
}

// bsonMarshall inputs a bson type and attempts to marshall it into a slice of bytes
func bsonMarshall(bsonData interface{}) (data []byte, err error) {
	switch t := bsonData.(type) {
	case nil:
		return nil, errors.New("input bsonData to marshall can not be nil")
	case []byte:
		return t, nil
	case bson.D:
		data, err = bson.Marshal(t)
		if err != nil {
			return
		}
	case bson.M:
		data, err = bson.Marshal(t)
		if err != nil {
			return
		}
	}
	return
}

// testMongoCollection
type testMongoCollection struct {
	name string
	ctx  context.Context
	docs []dbModel
}

// newTestMongoCollection
func newTestMongoCollection(name string) (*testMongoCollection, error) {
	if name == "" {
		return &testMongoCollection{}, errors.New("invalid test collection name")
	}
	testUserCollection := &testMongoCollection{name: name, docs: []dbModel{}}
	return testUserCollection, nil
}

// unmarshallBSON converts a BSON byte type back into a dbModel
func (coll *testMongoCollection) unmarshallBSON(bsonData interface{}) (dbModel, error) {
	switch coll.name {
	case "users":
		data, err := bsonMarshall(bsonData)
		if err != nil {
			return nil, err
		}
		um := userModel{}
		err = bson.Unmarshal(data, &um)
		return &um, nil
	case "groups":
		data, err := bsonMarshall(bsonData)
		if err != nil {
			return nil, err
		}
		gm := groupModel{}
		err = bson.Unmarshal(data, &gm)
		return &gm, nil
	case "blacklists":
		data, err := bsonMarshall(bsonData)
		if err != nil {
			return nil, err
		}
		bm := blacklistModel{}
		err = bson.Unmarshal(data, &bm)
		return &bm, nil
	}
	return nil, errors.New("invalid collection type: " + coll.name)
}

// findById in the test collection a document by ID
func (coll *testMongoCollection) findById(findId string) (reDoc dbModel, err error) {
	for _, doc := range coll.docs {
		var docId string
		docId, err = standardizeID(doc)
		if err != nil {
			return
		}
		if docId == findId {
			reDoc = doc
			return
		}
	}
	return reDoc, errors.New("document not found in test collection: " + findId)
}

// deleteById in the test collection a document by ID
func (coll *testMongoCollection) deleteById(findId string) (reDoc dbModel, err error) {
	var dbDocs []dbModel
	del := false
	for _, doc := range coll.docs {
		var docId string
		docId, err = standardizeID(doc)
		if err != nil {
			return
		}
		if docId != findId {
			dbDocs = append(dbDocs, doc)
		} else {
			reDoc = doc
			del = true
		}
	}
	if !del {
		return reDoc, errors.New("document not found in test collection: " + findId)
	}
	coll.docs = dbDocs
	return reDoc, nil
}

// updateById a document in the test collection
func (coll *testMongoCollection) updateById(findId string, upDoc dbModel) (reDoc dbModel, err error) {
	var dbDocs []dbModel
	up := false
	for _, doc := range coll.docs {
		var docId string
		docId, err = standardizeID(doc)
		if err != nil {
			return
		}
		if docId != findId {
			dbDocs = append(dbDocs, doc)
		} else {
			reDoc = doc
			bsonData, bErr := upDoc.toDoc()
			if bErr != nil {
				return reDoc, bErr
			}
			err = reDoc.update(bsonData)
			if err != nil {
				return reDoc, err
			}
			up = true
			dbDocs = append(dbDocs, reDoc)
		}
	}
	if !up {
		return reDoc, errors.New("document not found in test collection: " + findId)
	}
	coll.docs = dbDocs
	return reDoc, nil
}

// find documents in the test collection
func (coll *testMongoCollection) find(dbDoc dbModel) (reDocs []dbModel, err error) {
	for _, doc := range coll.docs {
		bsonData, bErr := dbDoc.toDoc()
		if bErr != nil {
			return reDocs, bErr
		}
		match := doc.match(bsonData)
		if match {
			reDocs = append(reDocs, dbDoc)
		}
	}
	return reDocs, nil
}

// insert documents into test collection
func (coll *testMongoCollection) insert(dbDocs []dbModel) (err error) {
	var valDocs []dbModel
	for _, dbDoc := range dbDocs {
		var docId string
		docId, err = standardizeID(dbDoc)
		if err != nil {
			return err
		}
		_, fErr := coll.findById(docId)
		if fErr != nil {
			valDocs = append(valDocs, dbDoc)
		}
	}
	coll.docs = append(coll.docs, valDocs...)
	return nil
}

// delete documents from the test collection
func (coll *testMongoCollection) delete(dbDocs []dbModel) (reDocs []dbModel, err error) {
	for _, dbDoc := range dbDocs {
		var docId string
		docId, err = standardizeID(dbDoc)
		if err != nil {
			return reDocs, err
		}
		reDoc, fErr := coll.deleteById(docId)
		if fErr == nil {
			reDocs = append(reDocs, reDoc)
		}
	}
	return reDocs, nil
}

// InsertOne into test collection
func (coll *testMongoCollection) InsertOne(ctx context.Context, document interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error) {
	coll.ctx = ctx
	fmt.Println(document, opts)
	doc := document.(dbModel)
	err := coll.insert([]dbModel{doc})
	return &mongo.InsertOneResult{InsertedID: doc.getID()}, err
}

// InsertMany into test collection
func (coll *testMongoCollection) InsertMany(ctx context.Context, documents []interface{}, opts ...*options.InsertManyOptions) (*mongo.InsertManyResult, error) {
	coll.ctx = ctx
	if len(documents) == 0 {
		return nil, mongo.ErrEmptySlice
	}
	fmt.Println(documents, opts)
	var inDocs []dbModel
	for _, d := range documents {
		inDocs = append(inDocs, d.(dbModel))
	}
	err := coll.insert(inDocs)
	if err != nil {
		return nil, err
	}
	var inIds []interface{}
	for _, inDoc := range inDocs {
		inIds = append(inIds, inDoc.getID())
	}
	imResult := &mongo.InsertManyResult{InsertedIDs: inIds}
	return imResult, err
}

// DeleteOne from test collection
func (coll *testMongoCollection) DeleteOne(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	var delCount int64
	coll.ctx = ctx
	fmt.Println(filter, opts)
	filterDoc, err := coll.unmarshallBSON(filter)
	if err != nil {
		return nil, err
	}
	delDocs, err := coll.delete([]dbModel{filterDoc})
	delCount = int64(len(delDocs))
	return &mongo.DeleteResult{DeletedCount: delCount}, nil
}

// FindOneAndDelete finds a document, deletes it from the test collection, and then returns the found document
func (coll *testMongoCollection) FindOneAndDelete(ctx context.Context, filter interface{}, opts ...*options.FindOneAndDeleteOptions) *mongo.SingleResult {
	var rawResult []byte
	coll.ctx = ctx
	fmt.Println(filter, opts)
	filterDoc, err := coll.unmarshallBSON(filter)
	if err == nil {
		delDocs, err := coll.delete([]dbModel{filterDoc})
		if err != nil && len(delDocs) > 0 {
			rawBson, err := delDocs[0].toDoc()
			if err != nil {
				rawResult, err = bsonMarshall(rawBson)
			}
		}
	}
	doc, err := bsonx.ReadDoc(rawResult)
	res := mongo.NewSingleResultFromDocument(doc, err, nil)
	return res
}

// UpdateOne a document in the test collection
func (coll *testMongoCollection) UpdateOne(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	coll.ctx = ctx
	fmt.Println(filter, update, opts)
	filterDoc, err := coll.unmarshallBSON(filter)
	if err == nil {
		return nil, err
	}
	docId, err := standardizeID(filterDoc)
	if err == nil {
		return nil, err
	}
	updateDoc, err := coll.unmarshallBSON(update)
	if err == nil {
		return nil, err
	}
	reDoc, err := coll.updateById(docId, updateDoc)
	return &mongo.UpdateResult{UpsertedID: reDoc.getID()}, err
}

// UpdateByID a document using an ID as the filter
func (coll *testMongoCollection) UpdateByID(ctx context.Context, id interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	if id == nil {
		return nil, mongo.ErrNilValue
	}
	fmt.Println(id, update, opts)
	return coll.UpdateOne(ctx, bson.D{{"_id", id}}, update, opts...)
}

// Find returns a collection of documents
func (coll *testMongoCollection) Find(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (cur *mongo.Cursor, err error) {
	var rawResults []byte
	coll.ctx = ctx
	fmt.Println(filter, opts)
	filterDoc, err := coll.unmarshallBSON(filter)
	if err == nil {
		return nil, err
	}
	reDocs, err := coll.find(filterDoc)
	cd := initTestCursorData(reDocs)
	bsonData, err := cd.toDoc()
	if err != nil {
		panic(err)
	}
	rawResults, err = bsonMarshall(bsonData)
	cur = &mongo.Cursor{Current: rawResults}
	return cur, nil
}

// FindOne returns a single test mongo document
func (coll *testMongoCollection) FindOne(ctx context.Context, filter interface{}, opts ...*options.FindOneOptions) *mongo.SingleResult {
	var rawResult []byte
	coll.ctx = ctx
	fmt.Println(filter, opts)
	filterDoc, err := coll.unmarshallBSON(filter)
	if err == nil {
		reDocs, err := coll.find(filterDoc)
		if err != nil && len(reDocs) > 0 {
			rawBson, err := reDocs[0].toDoc()
			if err != nil {
				rawResult, err = bsonMarshall(rawBson)
			}
		}
	}
	doc, err := bsonx.ReadDoc(rawResult)
	res := mongo.NewSingleResultFromDocument(doc, err, nil)
	return res
}

// CountDocuments in test mongodb collection
func (coll *testMongoCollection) CountDocuments(ctx context.Context, filter interface{}, opts ...*options.CountOptions) (int64, error) {
	var c int64
	coll.ctx = ctx
	fmt.Println(filter, opts)
	filterDoc, err := coll.unmarshallBSON(filter)
	if err == nil {
		return c, err
	}
	reDocs, err := coll.find(filterDoc)
	if err != nil {
		panic(err)
	}
	c = int64(len(reDocs))
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
