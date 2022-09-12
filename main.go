package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gofrs/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

/*
===================================UTILITY FUNCTIONS=============================================
*/

// generateUUID for index keying records of data
func generateUUID() (string, error) {
	curId, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return curId.String(), nil
}

// HandleOptionsRequest handles incoming OPTIONS request
func HandleOptionsRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Auth-Token, API-Key")
	w.Header().Add("Access-Control-Expose-Headers", "Content-Type, Auth-Token, API-Key")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Methods", "GET,DELETE,POST,PATCH")
	w.WriteHeader(http.StatusOK)
}

// SetResponseHeaders sets the response headers being sent back to the client
func SetResponseHeaders(w http.ResponseWriter, authToken string, apiKey string) http.ResponseWriter {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Auth-Token, API-Key")
	w.Header().Add("Access-Control-Expose-Headers", "Content-Type, Auth-Token, API-Key")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Methods", "GET,DELETE,POST,PATCH")
	if authToken != "" {
		w.Header().Add("Auth-Token", authToken)
	}
	if apiKey != "" {
		w.Header().Add("API-Key", apiKey)
	}
	return w
}

// jsonErr structures a standard error to return
type jsonErr struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

/*
===================================ROOT GROUP MODEL=============================================
*/

// Group is a root struct that is used to store the json encoded data for/from a mongodb group doc.
type Group struct {
	Id               string `json:"id,omitempty"`
	Uuid             string `json:"uuid,omitempty"`
	GroupType        string `json:"group_type,omitempty"`
	Name             string `json:"name,omitempty"`
	LastModified     string `json:"last_modified,omitempty"`
	CreationDatetime string `json:"creation_datetime,omitempty"`
}

// addTimeStamps updates a Group struct with a timestamp
func (g *Group) addTimeStamps(newRecord bool) {
	currentTime := time.Now().UTC()
	g.LastModified = currentTime.String()
	if newRecord {
		g.CreationDatetime = currentTime.String()
	}
}

// GroupService is an interface used to manage the relevant group doc controllers
type GroupService interface {
	GroupCreate(g *Group) (*Group, error)
	GroupsFind() ([]*Group, error)
}

/*
===================================DATABASE FUNCTIONALITY=============================================
*/

// DBClient manages a database connection
type DBClient struct {
	connectionURI string
	client        *mongo.Client
}

// initializeNewClient is a function that takes a mongoUri string and outputs a connected mongo client for the app to use
func initializeNewClient(mongoUri string) (*DBClient, error) {
	newDBClient := DBClient{connectionURI: mongoUri}
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

/*
===================================GROUP DB MODEL AND SERVICE=============================================
*/

// groupModel structures a group BSON document to save in a groups collection
type groupModel struct {
	Id               primitive.ObjectID `bson:"_id,omitempty"`
	Uuid             string             `bson:"uuid,omitempty"`
	GroupType        string             `bson:"group_type,omitempty"`
	Name             string             `bson:"name,omitempty"`
	LastModified     string             `bson:"last_modified,omitempty"`
	CreationDatetime string             `bson:"creation_datetime,omitempty"`
}

// newGroupModel initializes a new pointer to a groupModel struct from a pointer to a JSON Group struct
func newGroupModel(g *Group) *groupModel {
	return &groupModel{
		Uuid:             g.Uuid,
		GroupType:        g.GroupType,
		Name:             g.Name,
		LastModified:     g.LastModified,
		CreationDatetime: g.CreationDatetime,
	}
}

// toRootGroup creates and return a new pointer to a Group JSON struct from a pointer to a BSON groupModel
func (g *groupModel) toRootGroup() *Group {
	return &Group{
		Id:               g.Id.Hex(),
		Uuid:             g.Uuid,
		GroupType:        g.GroupType,
		Name:             g.Name,
		LastModified:     g.LastModified,
		CreationDatetime: g.CreationDatetime,
	}
}

// groupService is used by the app to manage all group related controllers and functionality
type groupService struct {
	collection *mongo.Collection
	client     *DBClient
}

// NewGroupService is an exported function used to initialize a new GroupService struct
func NewGroupService(dbClient *DBClient, dbName string, collectionName string) *groupService {
	collection := dbClient.client.Database(dbName).Collection(collectionName)
	return &groupService{collection, dbClient}
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

/*
===================================ROUTER FUNCTIONALITY=============================================
*/

type groupRouter struct {
	gService GroupService
}

// NewGroupRouter is a function that initializes a new groupRouter struct
func NewGroupRouter(router *mux.Router, g GroupService) *mux.Router {
	gRouter := groupRouter{g}
	router.HandleFunc("/groups", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/groups", gRouter.GroupsShow).Methods("GET")
	router.HandleFunc("/groups", gRouter.CreateGroup).Methods("POST")
	return router
}

// GroupsShow returns all groups to client
func (gr *groupRouter) GroupsShow(w http.ResponseWriter, r *http.Request) {
	w = SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	groups, err := gr.gService.GroupsFind()
	if err != nil {
		return
	}
	if err := json.NewEncoder(w).Encode(groups); err != nil {
		return
	}
}

// CreateGroup from a REST Request post body
func (gr *groupRouter) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var group Group
	group.GroupType = "normal"
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err = r.Body.Close(); err != nil {
		return
	}
	if err = json.Unmarshal(body, &group); err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err = json.NewEncoder(w).Encode(err); err != nil {
			return
		}
		return
	}
	group.Uuid, err = generateUUID()
	g, err := gr.gService.GroupCreate(&group)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(403)
		if err = json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
	} else {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusCreated)
		if err = json.NewEncoder(w).Encode(g); err != nil {
			return
		}
	}
}

/*
===================================SERVER FUNCTIONALITY=============================================
*/

// Server is a struct that stores the API Apps high level attributes such as the router, config, and services
type Server struct {
	Router       *mux.Router
	GroupService GroupService
}

// NewServer is a function used to initialize a new Server struct
func NewServer(g GroupService) *Server {
	router := mux.NewRouter().StrictSlash(true)
	router = NewGroupRouter(router, g)
	s := Server{Router: router, GroupService: g}
	return &s
}

// Start starts the initialized server
func (s *Server) Start() {
	log.Println("Listening on port 8080")
	if err := http.ListenAndServe(":8080", handlers.LoggingHandler(os.Stdout, s.Router)); err != nil {
		log.Fatal("http.ListenAndServe: ", err)
	}
}

/*
===================================APP FUNCTIONALITY=============================================
*/

// App is the highest level struct of the rest_api application. Stores the server, client, and config settings.
type App struct {
	server *Server
	client *DBClient
}

// Initialize is a function used to initialize a new instantiation of the API Application
func (a *App) Initialize(mongoURI string) error {
	var err error
	// 1) Initialize & Connect DB Client
	a.client, err = initializeNewClient(mongoURI)
	if err != nil {
		return err
	}
	err = a.client.Connect()
	if err != nil {
		return err
	}
	// 2) Initial DB Services
	gService := NewGroupService(a.client, "test2", "groups")
	// 3) Initial Servers
	a.server = NewServer(gService)
	return nil
}

// Run is a function used to run a previously initialized API Application
func (a *App) Run() {
	defer a.client.Close()
	a.server.Start()
}

/*
===================================MAIN FUNCTIONALITY=============================================
*/

func main() {
	var app App
	uriString := "<MONGODB URI STRING HERE>"
	err := app.Initialize(uriString)
	if err != nil {
		panic(err)
	}
	app.Run()
}
