package main

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"io"
	"net/http"
	"os"
	"time"
)

type userRouter struct {
	uService UserService
	gService GroupService
}

// NewUserRouter is a function that initializes a new userRouter struct
func NewUserRouter(router *mux.Router, u UserService, g GroupService, client *DBClient) *mux.Router {
	uRouter := userRouter{u, g}
	router.HandleFunc("/auth", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth", uRouter.Signin).Methods("POST")
	router.HandleFunc("/auth", MemberTokenVerifyMiddleWare(uRouter.RefreshSession, client)).Methods("GET")
	router.HandleFunc("/auth", MemberTokenVerifyMiddleWare(uRouter.Signout, client)).Methods("DELETE")
	router.HandleFunc("/auth/register", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth/register", uRouter.RegisterUser).Methods("POST")
	router.HandleFunc("/auth/api-key", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth/api-key", MemberTokenVerifyMiddleWare(uRouter.GenerateAPIKey, client)).Methods("GET")
	router.HandleFunc("/auth/password", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth/password", MemberTokenVerifyMiddleWare(uRouter.UpdatePassword, client)).Methods("POST")
	router.HandleFunc("/users", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/users", MemberTokenVerifyMiddleWare(uRouter.UsersShow, client)).Methods("GET")
	router.HandleFunc("/users/{userId}", HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/users/{userId}", MemberTokenVerifyMiddleWare(uRouter.UserShow, client)).Methods("GET")
	router.HandleFunc("/users", AdminTokenVerifyMiddleWare(uRouter.CreateUser, client)).Methods("POST")
	router.HandleFunc("/users/{userId}", AdminTokenVerifyMiddleWare(uRouter.DeleteUser, client)).Methods("DELETE")
	router.HandleFunc("/users/{userId}", MemberTokenVerifyMiddleWare(uRouter.ModifyUser, client)).Methods("PATCH")
	return router
}

// UpdatePassword is the handler function that manages the user password update process
func (ur *userRouter) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err := r.Body.Close(); err != nil {
		return
	}
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	type passwordStruct struct {
		NewPassword     string `json:"new_password"`
		CurrentPassword string `json:"current_password"`
	}
	var pw passwordStruct
	err = json.Unmarshal(body, &pw)
	if err != nil {
		return
	}
	u, err := ur.uService.UpdatePassword(decodedToken, pw.CurrentPassword, pw.NewPassword)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(403)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusAccepted)
		u.Password = ""
		if err := json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// ModifyUser is the handler function that updates a user
func (ur *userRouter) ModifyUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	var user User
	user.Uuid = userId
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err := r.Body.Close(); err != nil {
		return
	}
	if err := json.Unmarshal(body, &user); err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			return
		}
	}
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	user.GroupId = AdminRouteRoleCheck(decodedToken)
	u, err := ur.uService.UserUpdate(&user)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// Signin is the handler function that manages the user signin process
func (ur *userRouter) Signin(w http.ResponseWriter, r *http.Request) {
	var user User
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err := r.Body.Close(); err != nil {
		return
	}
	if err := json.Unmarshal(body, &user); err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			return
		}
	}
	u, err := ur.uService.AuthenticateUser(&user)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(401)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusUnauthorized, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		expDT := time.Now().Add(time.Hour * 1).Unix()
		sessionToken, err := CreateToken(u, expDT)
		if err != nil {
			return
		}
		w = SetResponseHeaders(w, sessionToken, "")
		w.WriteHeader(http.StatusOK)
		u.Password = ""
		if err := json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// RefreshSession is the handler function that refreshes a users JWT token
func (ur *userRouter) RefreshSession(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	tokenData, err := DecodeJWT(authToken)
	if err != nil {
		return
	}
	user, err := ur.uService.RefreshToken(tokenData)
	if err != nil {
		return
	}
	expDT := time.Now().Add(time.Hour * 1).Unix()
	newToken, err := CreateToken(user, expDT)
	if err != nil {
		return
	}
	w = SetResponseHeaders(w, newToken, "")
	w.WriteHeader(http.StatusOK)
}

// GenerateAPIKey is the handler function that generates 6 month API Key for a given user
func (ur *userRouter) GenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	tokenData, err := DecodeJWT(authToken)
	if err != nil {
		return
	}
	user, err := ur.uService.RefreshToken(tokenData)
	expDT := time.Now().Add(time.Hour * 4380).Unix()
	apiKey, err := CreateToken(user, expDT)
	if err != nil {
		return
	}
	w = SetResponseHeaders(w, "", apiKey)
	w.WriteHeader(http.StatusOK)
	return
}

// Signout is the handler function that ends a users session
func (ur *userRouter) Signout(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	ur.uService.BlacklistAuthToken(authToken)
	w = SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	return
}

// RegisterUser handler function that registers a new user
func (ur *userRouter) RegisterUser(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("REGISTRATION") == "OFF" {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(404)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: 404, Text: "Not Found"}); err != nil {
			return
		}
		return
	} else {
		var user User
		body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
		if err != nil {
			return
		}
		if err := r.Body.Close(); err != nil {
			return
		}
		if err := json.Unmarshal(body, &user); err != nil {
			w = SetResponseHeaders(w, "", "")
			w.WriteHeader(422)
			if err := json.NewEncoder(w).Encode(err); err != nil {
				return
			}
			return
		}
		var group Group
		groupName := user.Username
		groupName += "_group"
		group.Name = groupName
		group.GroupType = "normal"
		group.Uuid, err = generateUUID()
		if err != nil {
			return
		}
		g, err := ur.gService.GroupCreate(&group)
		if err != nil {
			w = SetResponseHeaders(w, "", "")
			w.WriteHeader(403)
			if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
				return
			}
			return
		}
		user.Role = "group_admin"
		user.GroupId = g.Uuid
		u, err := ur.uService.UserCreate(&user)
		if err != nil {
			w = SetResponseHeaders(w, "", "")
			w.WriteHeader(403)
			if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
				return
			}
			return
		} else {
			w = SetResponseHeaders(w, "", "")
			w.WriteHeader(http.StatusCreated)
			u.Password = ""
			if err := json.NewEncoder(w).Encode(u); err != nil {
				return
			}
			return
		}
	}
}

// CreateUser is the handler function that creates a new user
func (ur *userRouter) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user User
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err := r.Body.Close(); err != nil {
		return
	}
	if err := json.Unmarshal(body, &user); err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err := json.NewEncoder(w).Encode(err); err != nil {
			return
		}
		return
	}
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupUuid := AdminRouteRoleCheck(decodedToken)
	if groupUuid != "" {
		user.GroupId = groupUuid
	}
	u, err := ur.uService.UserCreate(&user)
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(403)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusCreated)
		u.Password = ""
		if err := json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// UsersShow is the handler that shows a specific user
func (ur *userRouter) UsersShow(w http.ResponseWriter, r *http.Request) {
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupUuid := AdminRouteRoleCheck(decodedToken)
	w = SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	users, err := ur.uService.UsersFind(&User{GroupId: groupUuid})
	if err := json.NewEncoder(w).Encode(users); err != nil {
		return
	}
	return
}

// UserShow is the handler that shows all users
func (ur *userRouter) UserShow(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupUuid := AdminRouteRoleCheck(decodedToken)
	user, err := ur.uService.UserFind(&User{Uuid: userId, GroupId: groupUuid})
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusNotFound, Text: err.Error()}); err != nil {
			return
		}
		return
	}
	user.Password = ""
	w = SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		panic(err)
	}
	return
}

// DeleteUser is the handler function that deletes a user
func (ur *userRouter) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	decodedToken, err := DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupUuid := AdminRouteRoleCheck(decodedToken)
	user, err := ur.uService.UserDelete(&User{Uuid: userId, GroupId: groupUuid})
	if err != nil {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusNotFound, Text: err.Error()}); err != nil {
			return
		}
		return
	}
	if user.Uuid != "" {
		w = SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode("User Deleted"); err != nil {
			return
		}
		return
	}
}
