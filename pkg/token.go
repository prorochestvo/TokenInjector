package tokeninjector

import (
	"time"
)

// Token is an interface that contains the methods for getting the user id, user name, role id, and expiration time.
type Token interface {
	UserID() string
	UserName() string
	UserRoleID() uint64
	ExpiredAt() time.Time
}

// token is a structure that contains the user id, user name, role id, and expiration time.
type token struct {
	userID    string
	userName  string
	roleID    uint64
	expiredAt time.Time
}

// UserID returns the user id.
func (t *token) UserID() string { return t.userID }

// UserName returns the user name.
func (t *token) UserName() string { return t.userName }

// UserRoleID returns the role id.
func (t *token) UserRoleID() uint64 { return t.roleID }

// ExpiredAt returns the expiration time.
func (t *token) ExpiredAt() time.Time { return t.expiredAt }
