package client

import (
	"net/http"
	"strings"
)

type Session struct {
	Name    string
	Cookies []*http.Cookie
	Headers map[string]string
}

type SessionManager struct {
	sessions map[string]*Session
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

func (sm *SessionManager) AddSession(name string, cookieStr string) {
	cookies := parseCookies(cookieStr)
	sm.sessions[name] = &Session{
		Name:    name,
		Cookies: cookies,
		Headers: make(map[string]string),
	}
}

func (sm *SessionManager) GetSession(name string) *Session {
	return sm.sessions[name]
}

func parseCookies(cookieStr string) []*http.Cookie {
	var cookies []*http.Cookie
	parts := strings.Split(cookieStr, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			cookies = append(cookies, &http.Cookie{
				Name:  kv[0],
				Value: kv[1],
			})
		}
	}
	return cookies
}
