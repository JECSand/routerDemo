package main

import "net/http"

// AuthService manages the functionality of platform authentication
type AuthService interface {
	BlacklistAuthToken(authToken string) error
	AdminTokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc
	MemberTokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc
}
