package tokeninjector

import (
	"context"
	"errors"
	"github.com/prorochestvo/tokeninjector/internal"
	"net/http"
	"strings"
	"time"
)

// TokenHandler is a middleware that extracts the user ID from the request and adds it to the request context.
// The token is extracted from the cookie and the header.
//   - secretKey: the secret key used to crypt and decrypt the token.
//   - cookieName: the name of the cookie that contains the token.
//   - contextBasicMethodKey: the key used to store the basic method token in the context.
//   - contextBearerMethodKey: the key used to store the bearer method token in the context.
//   - nextFunc: the next handler in the chain.
//
// IMPORTANT: does not return an error if the user ID is not found.
func TokenHandler(
	secretKey []byte,
	cookieName string,
	contextBasicMethodKey string,
	contextBearerMethodKey string,
	nextFunc http.HandlerFunc,
) (http.HandlerFunc, error) {
	var extractCookieToken = func(r *http.Request) (accessToken string) {
		if len(cookieName) == 0 {
			return
		}
		if h, err := r.Cookie(cookieName); err == nil && len(h.Value) > 0 {
			accessToken = strings.TrimSpace(h.Value)
		}
		return
	}
	var extractHeaderToken = func(r *http.Request) (method string, refreshToken string) {
		header := strings.TrimSpace(r.Header.Get(internal.HeaderAuthorization))
		if parts := strings.SplitN(header, " ", 2); len(parts) == 2 {
			method = parts[0]
			refreshToken = strings.TrimSpace(parts[1])
		}
		return
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if accessToken := extractCookieToken(r); len(accessToken) > 0 {
			userId, userName, roleId, expiredAt, err := Unmarshal(accessToken, secretKey)
			if err == nil && len(userId) > 0 && expiredAt.After(time.Now()) {
				t := &token{
					userID:    userId,
					userName:  userName,
					roleID:    roleId,
					expiredAt: expiredAt,
				}
				ctx = context.WithValue(ctx, internal.ContextKeyToken, t)
			}
		}

		if method, refreshToken := extractHeaderToken(r); len(refreshToken) > 0 {
			switch method {
			case internal.AuthMethodBasic:
				ctx = context.WithValue(ctx, contextBasicMethodKey, refreshToken)
			case internal.AuthMethodBearer:
				ctx = context.WithValue(ctx, contextBearerMethodKey, refreshToken)
			}
		}

		nextFunc(w, r.WithContext(ctx))
	}, nil
}

// ExtractToken extracts the token from the context.
// If the token is not found, an error is returned.
func ExtractToken(ctx context.Context) (Token, error) {
	t, ok := ctx.Value(internal.ContextKeyToken).(Token)
	if !ok {
		return nil, errors.New("token not found")
	}
	return t, nil
}
