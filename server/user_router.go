package server

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"io"
	"net/http"
	"os"
	"routerDemo/auth"
	"routerDemo/models"
	"routerDemo/services"
	"routerDemo/utilities"
)

type userRouter struct {
	aService *services.TokenService
	uService services.UserService
	gService services.GroupService
}

// NewUserRouter is a function that initializes a new userRouter struct
func NewUserRouter(router *mux.Router, a *services.TokenService, u services.UserService, g services.GroupService) *mux.Router {
	uRouter := userRouter{a, u, g}
	router.HandleFunc("/auth", utilities.HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth", uRouter.Signin).Methods("POST")
	router.HandleFunc("/auth", a.MemberTokenVerifyMiddleWare(uRouter.RefreshSession)).Methods("GET")
	router.HandleFunc("/auth", a.MemberTokenVerifyMiddleWare(uRouter.Signout)).Methods("DELETE")
	router.HandleFunc("/auth/register", utilities.HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth/register", uRouter.RegisterUser).Methods("POST")
	router.HandleFunc("/auth/api-key", utilities.HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth/api-key", a.MemberTokenVerifyMiddleWare(uRouter.GenerateAPIKey)).Methods("GET")
	router.HandleFunc("/auth/password", utilities.HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/auth/password", a.MemberTokenVerifyMiddleWare(uRouter.UpdatePassword)).Methods("POST")
	router.HandleFunc("/users", utilities.HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/users", a.MemberTokenVerifyMiddleWare(uRouter.UsersShow)).Methods("GET")
	router.HandleFunc("/users/{userId}", utilities.HandleOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/users/{userId}", a.MemberTokenVerifyMiddleWare(uRouter.UserShow)).Methods("GET")
	router.HandleFunc("/users", a.AdminTokenVerifyMiddleWare(uRouter.CreateUser)).Methods("POST")
	router.HandleFunc("/users/{userId}", a.AdminTokenVerifyMiddleWare(uRouter.DeleteUser)).Methods("DELETE")
	router.HandleFunc("/users/{userId}", a.MemberTokenVerifyMiddleWare(uRouter.ModifyUser)).Methods("PATCH")
	return router
}

// UpdatePassword is the handler function that manages the user password update process
func (ur *userRouter) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err = r.Body.Close(); err != nil {
		return
	}
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
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
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(403)
		if err = json.NewEncoder(w).Encode(utilities.JsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusAccepted)
		u.Password = ""
		if err = json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// ModifyUser is the handler function that updates a user
func (ur *userRouter) ModifyUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	var user models.User
	user.Id = userId
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err = r.Body.Close(); err != nil {
		return
	}
	if err = json.Unmarshal(body, &user); err != nil {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err = json.NewEncoder(w).Encode(err); err != nil {
			return
		}
		return
	}
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	groupId := decodedToken.AdminRouteRoleCheck()
	if groupId != "" { // Force Scope the groupId to the groupId of the Token if user is not RootAdmin
		user.GroupId = groupId
		user.RootAdmin = false
	}
	u, err := ur.uService.UserUpdate(&user)
	if err != nil {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusForbidden)
		if err = json.NewEncoder(w).Encode(utilities.JsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusAccepted)
		if err = json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// Signin is the handler function that manages the user signin process
func (ur *userRouter) Signin(w http.ResponseWriter, r *http.Request) {
	var user models.User
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err = r.Body.Close(); err != nil {
		return
	}
	if err = json.Unmarshal(body, &user); err != nil {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err = json.NewEncoder(w).Encode(err); err != nil {
			return
		}
		return
	}
	u, err := ur.uService.AuthenticateUser(&user)
	if err != nil {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(401)
		if err = json.NewEncoder(w).Encode(utilities.JsonErr{Code: http.StatusUnauthorized, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		sessionToken, err := ur.aService.GenerateToken(u, "session")
		if err != nil {
			return
		}
		w = utilities.SetResponseHeaders(w, sessionToken, "")
		w.WriteHeader(http.StatusOK)
		u.Password = ""
		if err = json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// RefreshSession is the handler function that refreshes a users JWT token
func (ur *userRouter) RefreshSession(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	tokenData, err := auth.DecodeJWT(authToken)
	if err != nil {
		return
	}
	user, err := ur.uService.UserFind(tokenData.ToUser())
	if err != nil {
		return
	}
	newToken, err := ur.aService.GenerateToken(user, "session")
	if err != nil {
		return
	}
	w = utilities.SetResponseHeaders(w, newToken, "")
	w.WriteHeader(http.StatusOK)
}

// GenerateAPIKey is the handler function that generates 6 month API Key for a given user
func (ur *userRouter) GenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	tokenData, err := auth.DecodeJWT(authToken)
	if err != nil {
		return
	}
	user, err := ur.uService.UserFind(tokenData.ToUser())
	apiKey, err := ur.aService.GenerateToken(user, "api")
	if err != nil {
		return
	}
	w = utilities.SetResponseHeaders(w, "", apiKey)
	w.WriteHeader(http.StatusOK)
	return
}

// Signout is the handler function that ends a users session
func (ur *userRouter) Signout(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	err := ur.aService.BlacklistAuthToken(authToken)
	if err != nil {
		return
	}
	w = utilities.SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	return
}

// RegisterUser handler function that registers a new user
func (ur *userRouter) RegisterUser(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("REGISTRATION") == "OFF" {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(404)
		if err := json.NewEncoder(w).Encode(utilities.JsonErr{Code: 404, Text: "Not Found"}); err != nil {
			return
		}
		return
	} else {
		var user models.User
		body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
		if err != nil {
			return
		}
		if err = r.Body.Close(); err != nil {
			return
		}
		if err = json.Unmarshal(body, &user); err != nil {
			w = utilities.SetResponseHeaders(w, "", "")
			w.WriteHeader(422)
			if err = json.NewEncoder(w).Encode(err); err != nil {
				return
			}
			return
		}
		var group models.Group
		groupName := user.Email
		groupName += "_group"
		group.Name = groupName
		group.Id = utilities.GenerateObjectID()
		group.RootAdmin = false
		g, err := ur.gService.GroupCreate(&group)
		if err != nil {
			w = utilities.SetResponseHeaders(w, "", "")
			w.WriteHeader(403)
			if err = json.NewEncoder(w).Encode(utilities.JsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
				return
			}
			return
		}
		user.Role = "admin"
		user.GroupId = g.Id
		u, err := ur.uService.UserCreate(&user)
		if err != nil {
			w = utilities.SetResponseHeaders(w, "", "")
			w.WriteHeader(403)
			if err = json.NewEncoder(w).Encode(utilities.JsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
				return
			}
			return
		} else {
			newToken, err := ur.aService.GenerateToken(u, "session")
			if err != nil {
				return
			}
			w = utilities.SetResponseHeaders(w, newToken, "")
			w.WriteHeader(http.StatusCreated)
			u.Password = ""
			if err = json.NewEncoder(w).Encode(u); err != nil {
				return
			}
			return
		}
	}
}

// CreateUser is the handler function that creates a new user
func (ur *userRouter) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user models.User
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return
	}
	if err = r.Body.Close(); err != nil {
		return
	}
	if err = json.Unmarshal(body, &user); err != nil {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(422)
		if err = json.NewEncoder(w).Encode(err); err != nil {
			return
		}
		return
	}
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupId := decodedToken.AdminRouteRoleCheck()
	if groupId != "" { // Force Scope the groupId to the groupId of the Token if user is not RootAdmin
		user.GroupId = groupId
		user.RootAdmin = false
	}
	u, err := ur.uService.UserCreate(&user)
	if err != nil {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(403)
		if err = json.NewEncoder(w).Encode(utilities.JsonErr{Code: http.StatusForbidden, Text: err.Error()}); err != nil {
			return
		}
		return
	} else {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusCreated)
		u.Password = ""
		if err = json.NewEncoder(w).Encode(u); err != nil {
			return
		}
		return
	}
}

// UsersShow is the handler that shows a specific user
func (ur *userRouter) UsersShow(w http.ResponseWriter, r *http.Request) {
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupId := decodedToken.AdminRouteRoleCheck()
	w = utilities.SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	users, err := ur.uService.UsersFind(&models.User{GroupId: groupId})
	if err = json.NewEncoder(w).Encode(users); err != nil {
		return
	}
	return
}

// UserShow is the handler that shows all users
func (ur *userRouter) UserShow(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupId := decodedToken.AdminRouteRoleCheck()
	user, err := ur.uService.UserFind(&models.User{Id: userId, GroupId: groupId})
	if err != nil {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusNotFound)
		if err = json.NewEncoder(w).Encode(utilities.JsonErr{Code: http.StatusNotFound, Text: err.Error()}); err != nil {
			return
		}
		return
	}
	user.Password = ""
	w = utilities.SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	if err = json.NewEncoder(w).Encode(user); err != nil {
		return
	}
	return
}

// DeleteUser is the handler function that deletes a user
func (ur *userRouter) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		return
	}
	groupId := decodedToken.AdminRouteRoleCheck()
	user, err := ur.uService.UserDelete(&models.User{Id: userId, GroupId: groupId})
	if err != nil {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusNotFound)
		if err = json.NewEncoder(w).Encode(utilities.JsonErr{Code: http.StatusNotFound, Text: err.Error()}); err != nil {
			return
		}
		return
	}
	if user.Id != "" {
		w = utilities.SetResponseHeaders(w, "", "")
		w.WriteHeader(http.StatusOK)
		if err = json.NewEncoder(w).Encode("User Deleted"); err != nil {
			return
		}
		return
	}
}
