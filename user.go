package main

import "time"

// User is a root struct that is used to store the json encoded data for/from a mongodb user doc.
type User struct {
	Id           string    `json:"id,omitempty"`
	Username     string    `json:"username,omitempty"`
	Password     string    `json:"password,omitempty"`
	FirstName    string    `json:"firstname,omitempty"`
	LastName     string    `json:"lastname,omitempty"`
	Email        string    `json:"email,omitempty"`
	Role         string    `json:"role,omitempty"`
	RootAdmin    bool      `json:"root_admin,omitempty"`
	GroupId      string    `json:"group_id,omitempty"`
	LastModified time.Time `json:"last_modified,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
	DeletedAt    time.Time `json:"deleted_at,omitempty"`
}

// BuildUpdate is a function that setups the base user struct during a user modification request
func (g *User) BuildUpdate(curUser *userModel) {
	if len(g.Username) == 0 {
		g.Username = curUser.Username
	}
	if len(g.FirstName) == 0 {
		g.FirstName = curUser.FirstName
	}
	if len(g.LastName) == 0 {
		g.LastName = curUser.LastName
	}
	if len(g.Email) == 0 {
		g.Email = curUser.Email
	}
	if len(g.GroupId) == 0 {
		g.GroupId = curUser.GroupId.Hex()
	}
	if len(g.Role) == 0 {
		g.Role = curUser.Role
	}
}

// UserService is an interface used to manage the relevant user doc controllers
type UserService interface {
	AuthenticateUser(u *User) (*User, error)
	BlacklistAuthToken(authToken string) error
	RefreshToken(tokenData *TokenData) (*User, error)
	UpdatePassword(tokenData *TokenData, CurrentPassword string, newPassword string) (*User, error)
	UserCreate(u *User) (*User, error)
	UserDelete(u *User) (*User, error)
	UsersFind(u *User) ([]*User, error)
	UserFind(u *User) (*User, error)
	UserUpdate(u *User) (*User, error)
	UserDocInsert(u *User) (*User, error)
}
