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
	router.HandleFunc("/auth", uRouter.SignIn).Methods("POST")
	router.HandleFunc("/auth", a.MemberTokenVerifyMiddleWare(uRouter.RefreshSession)).Methods("GET")
	router.HandleFunc("/auth", a.MemberTokenVerifyMiddleWare(uRouter.SignOut)).Methods("DELETE")
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
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = r.Body.Close(); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	type passwordStruct struct {
		NewPassword     string `json:"new_password"`
		CurrentPassword string `json:"current_password"`
	}
	var pw passwordStruct
	err = json.Unmarshal(body, &pw)
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	inUser := decodedToken.ToUser()
	u, err := ur.uService.UpdatePassword(inUser, pw.CurrentPassword, pw.NewPassword)
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
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
	if userId == "" || userId == "000000000000000000000000" {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: "missing userId"})
		return
	}
	var user models.User
	user.Id = userId
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = r.Body.Close(); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = json.Unmarshal(body, &user); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	groupId := decodedToken.AdminRouteRoleCheck()
	if groupId != "" { // Force Scope the groupId to the groupId of the Token if user is not RootAdmin
		user.GroupId = groupId
		user.RootAdmin = false
	}
	u, err := ur.uService.UserUpdate(&user)
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
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

// SignIn is the handler function that manages the user SignIn process
func (ur *userRouter) SignIn(w http.ResponseWriter, r *http.Request) {
	var user models.User
	body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = r.Body.Close(); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = json.Unmarshal(body, &user); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	u, err := ur.uService.AuthenticateUser(&user)
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	} else {
		sessionToken, err := ur.aService.GenerateToken(u, "session")
		if err != nil {
			utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
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
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	user, err := ur.uService.UserFind(tokenData.ToUser())
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	newToken, err := ur.aService.GenerateToken(user, "session")
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	w = utilities.SetResponseHeaders(w, newToken, "")
	w.WriteHeader(http.StatusOK)
	return
}

// GenerateAPIKey is the handler function that generates 6 month API Key for a given user
func (ur *userRouter) GenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	tokenData, err := auth.DecodeJWT(authToken)
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	user, err := ur.uService.UserFind(tokenData.ToUser())
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	apiKey, err := ur.aService.GenerateToken(user, "api")
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	w = utilities.SetResponseHeaders(w, "", apiKey)
	w.WriteHeader(http.StatusOK)
	return
}

// SignOut is the handler function that ends a users session
func (ur *userRouter) SignOut(w http.ResponseWriter, r *http.Request) {
	authToken := r.Header.Get("Auth-Token")
	err := ur.aService.BlacklistAuthToken(authToken)
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	w = utilities.SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	return
}

// RegisterUser handler function that registers a new user
func (ur *userRouter) RegisterUser(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("REGISTRATION") == "OFF" {
		utilities.RespondWithError(w, http.StatusNotFound, utilities.JWTError{Message: "Not Found"})
		return
	} else {
		var user models.User
		body, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
		if err != nil {
			utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
			return
		}
		if err = r.Body.Close(); err != nil {
			utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
			return
		}
		if err = json.Unmarshal(body, &user); err != nil {
			utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
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
			utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
			return
		}
		user.Role = "admin"
		user.GroupId = g.Id
		u, err := ur.uService.UserCreate(&user)
		if err != nil {
			utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
			return
		} else {
			newToken, err := ur.aService.GenerateToken(u, "session")
			if err != nil {
				utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
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
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = r.Body.Close(); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = json.Unmarshal(body, &user); err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	groupId := decodedToken.AdminRouteRoleCheck()
	if groupId != "" { // Force Scope the groupId to the groupId of the Token if user is not RootAdmin
		user.GroupId = groupId
		user.RootAdmin = false
	}
	u, err := ur.uService.UserCreate(&user)
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
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
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	groupId := decodedToken.AdminRouteRoleCheck()
	w = utilities.SetResponseHeaders(w, "", "")
	w.WriteHeader(http.StatusOK)
	users, err := ur.uService.UsersFind(&models.User{GroupId: groupId})
	if err != nil {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: err.Error()})
		return
	}
	if err = json.NewEncoder(w).Encode(users); err != nil {
		return
	}
	return
}

// UserShow is the handler that shows all users
func (ur *userRouter) UserShow(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	if userId == "" || userId == "000000000000000000000000" {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: "missing userId"})
		return
	}
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	groupId := decodedToken.AdminRouteRoleCheck()
	user, err := ur.uService.UserFind(&models.User{Id: userId, GroupId: groupId})
	if err != nil {
		utilities.RespondWithError(w, http.StatusNotFound, utilities.JWTError{Message: err.Error()})
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
	if userId == "" || userId == "000000000000000000000000" {
		utilities.RespondWithError(w, http.StatusBadRequest, utilities.JWTError{Message: "missing userId"})
		return
	}
	decodedToken, err := auth.DecodeJWT(r.Header.Get("Auth-Token"))
	if err != nil {
		utilities.RespondWithError(w, http.StatusUnauthorized, utilities.JWTError{Message: err.Error()})
		return
	}
	groupId := decodedToken.AdminRouteRoleCheck()
	user, err := ur.uService.UserDelete(&models.User{Id: userId, GroupId: groupId})
	if err != nil {
		utilities.RespondWithError(w, http.StatusNotFound, utilities.JWTError{Message: err.Error()})
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
