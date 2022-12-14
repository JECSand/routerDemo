package server

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"io"
	"net/http"
	"routerDemo/models"
	"routerDemo/services"
	"routerDemo/utilities"
)

type groupRouter struct {
	aService *services.TokenService
	gService services.GroupService
}

// NewGroupRouter is a function that initializes a new groupRouter struct
func NewGroupRouter(router *mux.Router, a *services.TokenService, g services.GroupService) *mux.Router {
	gRouter := groupRouter{a, g}
	router.HandleFunc("/groups", utilities.HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/groups", a.AdminTokenVerifyMiddleWare(gRouter.GroupsShow)).Methods("GET")
	router.HandleFunc("/groups", a.AdminTokenVerifyMiddleWare(gRouter.CreateGroup)).Methods("POST")
	router.HandleFunc("/groups/{groupId}", utilities.HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/groups/{groupId}", a.AdminTokenVerifyMiddleWare(gRouter.GroupShow)).Methods("GET")
	router.HandleFunc("/groups", a.AdminTokenVerifyMiddleWare(gRouter.CreateGroup)).Methods("POST")
	router.HandleFunc("/groups/{groupId}", a.AdminTokenVerifyMiddleWare(gRouter.DeleteGroup)).Methods("DELETE")
	router.HandleFunc("/groups/{groupId}", a.AdminTokenVerifyMiddleWare(gRouter.ModifyGroup)).Methods("PATCH")
	return router
}

// GroupsShow returns all groups to client
func (gr *groupRouter) GroupsShow(w http.ResponseWriter, r *http.Request) {
	w = utilities.SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	groups, err := gr.gService.GroupsFind()
	if err != nil {
		utilities.RespondWithError(w, http.StatusServiceUnavailable, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = json.NewEncoder(w).Encode(groups); err != nil {
		return
	}
}

// CreateGroup from a REST Request post body
func (gr *groupRouter) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var group models.Group
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = r.Body.Close(); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = json.Unmarshal(body, &group); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	group.Id = utilities.GenerateObjectID()
	group.RootAdmin = false
	g, err := gr.gService.GroupCreate(&group)
	if err != nil {
		utilities.RespondWithError(w, http.StatusServiceUnavailable, utilities.JWTError{Message: err.Error()})
		return
	} else {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusCreated)
		if err = json.NewEncoder(w).Encode(g); err != nil {
			return
		}
	}
}

// ModifyGroup to update a group document
func (gr *groupRouter) ModifyGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupId := vars["groupId"]
	if groupId == "" || groupId == "000000000000000000000000" {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: "missing groupId"})
		return
	}
	var group models.Group
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = r.Body.Close(); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = json.Unmarshal(body, &group); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	group.Id = groupId
	g, err := gr.gService.GroupUpdate(&group)
	if err != nil {
		utilities.RespondWithError(w, http.StatusServiceUnavailable, utilities.JWTError{Message: err.Error()})
		return
	} else {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusAccepted)
		if err = json.NewEncoder(w).Encode(g); err != nil {
			return
		}
	}
}

// GroupShow shows a specific group
func (gr *groupRouter) GroupShow(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupId := vars["groupId"]
	if groupId == "" || groupId == "000000000000000000000000" {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: "missing groupId"})
		return
	}
	group, err := gr.gService.GroupFind(&models.Group{Id: groupId})
	if err != nil {
		utilities.RespondWithError(w, http.StatusNotFound, utilities.JWTError{Message: err.Error()})
		return
	}
	w = utilities.SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	if err = json.NewEncoder(w).Encode(group); err != nil {
		return
	}
	return
}

// DeleteGroup deletes a group
func (gr *groupRouter) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupId := vars["groupId"]
	if groupId == "" || groupId == "000000000000000000000000" {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: "missing groupId"})
		return
	}
	group, err := gr.gService.GroupDelete(&models.Group{Id: groupId})
	if err != nil {
		utilities.RespondWithError(w, http.StatusNotFound, utilities.JWTError{Message: err.Error()})
		return
	}
	w = utilities.SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	if err = json.NewEncoder(w).Encode(group); err != nil {
		return
	}
	return
}
