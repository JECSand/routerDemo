package main

import (
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
)

// Server is a struct that stores the API Apps high level attributes such as the router, config, and services
type Server struct {
	Router       *mux.Router
	UserService  UserService
	GroupService GroupService
}

// NewServer is a function used to initialize a new Server struct
func NewServer(u UserService, g GroupService, db *DBClient) *Server {
	router := mux.NewRouter().StrictSlash(true)
	router = NewGroupRouter(router, g, db)
	router = NewUserRouter(router, u, g, db)
	s := Server{Router: router, UserService: u, GroupService: g}
	return &s
}

// Start starts the initialized server
func (s *Server) Start() {
	log.Println("Listening on port 8080")
	if err := http.ListenAndServe(":8080", handlers.LoggingHandler(os.Stdout, s.Router)); err != nil {
		log.Fatal("http.ListenAndServe: ", err)
	}
}
