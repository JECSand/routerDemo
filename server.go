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
	AuthService  AuthService
	UserService  UserService
	GroupService GroupService
}

// NewServer is a function used to initialize a new Server struct
func NewServer(u UserService, g GroupService, aService AuthService) *Server {
	router := mux.NewRouter().StrictSlash(true)
	router = NewGroupRouter(router, aService, g)
	router = NewUserRouter(router, aService, u, g)
	s := Server{Router: router, AuthService: aService, UserService: u, GroupService: g}
	return &s
}

// Start starts the initialized server
func (s *Server) Start() {
	log.Println("Listening on port 8080")
	if err := http.ListenAndServe(":8080", handlers.LoggingHandler(os.Stdout, s.Router)); err != nil {
		log.Fatal("http.ListenAndServe: ", err)
	}
}
