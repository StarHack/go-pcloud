package pcloud

import (
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"sync/atomic"
	"time"
)

const (
	oauthPort       = 65432
	redirectURLBase = "http://localhost:65432/"
	authorizeURL    = "https://my.pcloud.com/oauth2/authorize"
)

type tokenServer struct {
	code     atomic.Value
	hostname atomic.Value
}

type TokenHandler struct {
	ClientID   string
	Redirect   string
	Authorize  string
	openHook   func(string) error
	closeHook  func() error
	httpServer *http.Server
}

func DefaultTokenHandler(clientID string) *TokenHandler {
	return &TokenHandler{
		ClientID:  clientID,
		Redirect:  redirectURLBase,
		Authorize: authorizeURL,
		openHook:  openBrowser,
		closeHook: func() error { return nil },
	}
}

func (t *TokenHandler) GetAccessToken() (string, string, error) {
	authURL := fmt.Sprintf("%s?response_type=code&redirect_uri=%s&client_id=%s", t.Authorize, url.QueryEscape(t.Redirect), url.QueryEscape(t.ClientID))
	s := &tokenServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := q.Get("code")
		host := q.Get("hostname")
		if code != "" {
			s.code.Store(code)
			if host == "" {
				host = "api.pcloud.com"
			}
			s.hostname.Store(host)
			_, _ = w.Write([]byte("<html><h1>You may now close this window.</h1></html>"))
		} else {
			http.NotFound(w, r)
		}
	})
	server := &http.Server{Addr: fmt.Sprintf(":%d", oauthPort), Handler: mux}
	t.httpServer = server
	go server.ListenAndServe()
	_ = t.openHook(authURL)
	defer server.Close()
	for {
		if c, ok := s.code.Load().(string); ok && c != "" {
			h, _ := s.hostname.Load().(string)
			return c, h, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

