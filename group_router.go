package main

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"io"
	"net/http"
)

type groupRouter struct {
	aService AuthService
	gService GroupService
}

// NewGroupRouter is a function that initializes a new groupRouter struct
func NewGroupRouter(router *mux.Router, a AuthService, g GroupService) *mux.Router {
	gRouter := groupRouter{a, g}
	router.HandleFunc("/groups", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/groups", a.AdminTokenVerifyMiddleWare(gRouter.GroupsShow)).Methods("GET")
	router.HandleFunc("/groups", a.AdminTokenVerifyMiddleWare(gRouter.CreateGroup)).Methods("POST")
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
	group.Id = generateObjectID()
	group.RootAdmin = false
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
