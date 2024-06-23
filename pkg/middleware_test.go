package tokeninjector

import (
	"fmt"
	"github.com/prorochestvo/tokeninjector/internal"
	"github.com/twinj/uuid"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokenHandler_HeaderCookie_ActiveToken(t *testing.T) {
	secretKey := uuid.NewV4().Bytes()
	userID := uuid.NewV4().String()
	userName := uuid.NewV4().String()
	userRoleID := rand.Uint64()

	cookieName := uuid.NewV4().String()
	cookieValue, err := Marshal(userID, userName, userRoleID, time.Now().Add(time.Hour), secretKey)
	if err != nil {
		t.Fatal(err)
	}

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue, HttpOnly: true})

	basicMethodKey := uuid.NewV4().String()
	bearerMethodKey := uuid.NewV4().String()

	h, err := TokenHandler(secretKey, cookieName, basicMethodKey, bearerMethodKey, func(w http.ResponseWriter, r *http.Request) {
		defer func(Body io.ReadCloser) {
			if e := Body.Close(); e != nil {
				_, _ = w.Write([]byte(e.Error()))
			}
		}(r.Body)
		if _, ok := r.Context().Value(basicMethodKey).(string); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, ok := r.Context().Value(bearerMethodKey).(string); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		v, ok := r.Context().Value(internal.ContextKeyToken).(Token)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("UserID: %s; UserName: %s; UserRoleID: %d;", v.UserID(), v.UserName(), v.UserRoleID())))
	})
	if err != nil {
		t.Errorf("could not create nextHandler; details: %s", err.Error())
	}

	h(res, req)
	if res.Code != http.StatusOK {
		t.Errorf("incorrect response code, got %d", res.Code)
	}
	if s := res.Body.String(); !strings.Contains(s, userID) {
		t.Errorf("incorrect response body, got %s", s)
	} else if !strings.Contains(s, userName) {
		t.Errorf("incorrect response body, got %s", s)
	} else if !strings.Contains(s, fmt.Sprintf("%d", userRoleID)) {
		t.Errorf("incorrect response body, got %s", s)
	}
}

func TestTokenHandler_HeaderCookie_InactiveToken(t *testing.T) {
	secretKey := uuid.NewV4().Bytes()
	userID := uuid.NewV4().String()
	userName := uuid.NewV4().String()
	userRoleID := rand.Uint64()

	cookieName := uuid.NewV4().String()
	cookieValue, err := Marshal(userID, userName, userRoleID, time.Now().Add(-time.Hour), secretKey)
	if err != nil {
		t.Fatal(err)
	}

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue, HttpOnly: true})

	basicMethodKey := uuid.NewV4().String()
	bearerMethodKey := uuid.NewV4().String()

	h, err := TokenHandler(secretKey, cookieName, basicMethodKey, bearerMethodKey, func(w http.ResponseWriter, r *http.Request) {
		defer func(Body io.ReadCloser) {
			if e := Body.Close(); e != nil {
				_, _ = w.Write([]byte(e.Error()))
			}
		}(r.Body)
		if _, ok := r.Context().Value(basicMethodKey).(string); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, ok := r.Context().Value(bearerMethodKey).(string); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, ok := r.Context().Value(internal.ContextKeyToken).(Token); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	if err != nil {
		t.Errorf("could not create nextHandler; details: %s", err.Error())
	}

	h(res, req)
	if res.Code != http.StatusOK {
		t.Errorf("incorrect response code, got %d", res.Code)
	}
}

func TestTokenHandler_HeaderBasicAuthorization(t *testing.T) {
	secretKey := uuid.NewV4().Bytes()
	cookieName := uuid.NewV4().String()
	headerValue := uuid.NewV4().String()

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(internal.HeaderAuthorization, fmt.Sprintf("%s %s", internal.AuthMethodBasic, headerValue))

	basicMethodKey := uuid.NewV4().String()
	bearerMethodKey := uuid.NewV4().String()

	h, err := TokenHandler(secretKey, cookieName, basicMethodKey, bearerMethodKey, func(w http.ResponseWriter, r *http.Request) {
		defer func(Body io.ReadCloser) {
			if e := Body.Close(); e != nil {
				_, _ = w.Write([]byte(e.Error()))
			}
		}(r.Body)
		if _, ok := r.Context().Value(internal.ContextKeyToken).(Token); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, ok := r.Context().Value(bearerMethodKey).(Token); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		v, ok := r.Context().Value(basicMethodKey).(string)
		if !ok || len(v) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(v))
	})
	if err != nil {
		t.Errorf("could not create nextHandler; details: %s", err.Error())
	}

	h(res, req)
	if res.Code != http.StatusOK {
		t.Errorf("incorrect response code, got %d", res.Code)
	}
	if s := res.Body.String(); !strings.Contains(s, headerValue) {
		t.Errorf("incorrect response body, got %s", s)
	}
}

func TestTokenHandler_HeaderBearerAuthorization(t *testing.T) {
	secretKey := uuid.NewV4().Bytes()
	cookieName := uuid.NewV4().String()
	headerValue := uuid.NewV4().String()

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(internal.HeaderAuthorization, fmt.Sprintf("%s %s", internal.AuthMethodBearer, headerValue))

	basicMethodKey := uuid.NewV4().String()
	bearerMethodKey := uuid.NewV4().String()

	h, err := TokenHandler(secretKey, cookieName, basicMethodKey, bearerMethodKey, func(w http.ResponseWriter, r *http.Request) {
		defer func(Body io.ReadCloser) {
			if e := Body.Close(); e != nil {
				_, _ = w.Write([]byte(e.Error()))
			}
		}(r.Body)
		if _, ok := r.Context().Value(internal.ContextKeyToken).(Token); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, ok := r.Context().Value(basicMethodKey).(Token); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		v, ok := r.Context().Value(bearerMethodKey).(string)
		if !ok || len(v) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(v))
	})
	if err != nil {
		t.Errorf("could not create nextHandler; details: %s", err.Error())
	}

	h(res, req)
	if res.Code != http.StatusOK {
		t.Errorf("incorrect response code, got %d", res.Code)
	}
	if s := res.Body.String(); !strings.Contains(s, headerValue) {
		t.Errorf("incorrect response body, got %s", s)
	}
}

func TestTokenHandler_Unauthorized(t *testing.T) {
	secretKey := uuid.NewV4().Bytes()
	cookieName := uuid.NewV4().String()

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	basicMethodKey := uuid.NewV4().String()
	bearerMethodKey := uuid.NewV4().String()

	h, err := TokenHandler(secretKey, cookieName, basicMethodKey, bearerMethodKey, func(w http.ResponseWriter, r *http.Request) {
		defer func(Body io.ReadCloser) {
			if e := Body.Close(); e != nil {
				_, _ = w.Write([]byte(e.Error()))
			}
		}(r.Body)
		if _, ok := r.Context().Value(internal.ContextKeyToken).(Token); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, ok := r.Context().Value(basicMethodKey).(string); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, ok := r.Context().Value(bearerMethodKey).(string); ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	if err != nil {
		t.Errorf("could not create nextHandler; details: %s", err.Error())
	}

	h(res, req)
	if res.Code != http.StatusOK {
		t.Errorf("incorrect response code, got %d", res.Code)
	}
}
