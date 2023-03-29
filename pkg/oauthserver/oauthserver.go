package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/pzingg/gotosocial-client/pkg/common"
)

type OAuthServer struct {
	Ctx       context.Context
	CtxCancel context.CancelFunc
	Origin    string
	Responses chan common.JsonResponse

	httpServer *http.Server
}

type AuthorizeResp struct {
	State string `json:"state"`
	Code  string `json:"code"`
}

// URL path on our server
const RedirectPath = "/oauth/callback"

func NewOAuthServer(ctx context.Context, port int) *OAuthServer {
	addr := fmt.Sprintf(":%d", port)
	origin := fmt.Sprintf("http://localhost:%d", port)

	oas := &OAuthServer{Origin: origin, Responses: make(chan common.JsonResponse)}
	oas.Ctx, oas.CtxCancel = signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)

	mux := http.NewServeMux()
	mux.HandleFunc(RedirectPath, oas.callbackGETHandler)
	oas.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
		BaseContext: func(l net.Listener) context.Context {
			return oas.Ctx
		},
	}

	go oas.start()
	return oas
}

func (oas *OAuthServer) start() {
	log.Println("Starting oauth server")
	defer oas.CtxCancel()

	err := oas.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		log.Println("Oauth server closed")
	} else if err != nil {
		log.Printf("Oauth server error listening: %s\n", err)
	} else {
		oas.Shutdown()
		log.Println("Oauth server stopped gracefully")
	}
}

func (oas *OAuthServer) Shutdown() {
	log.Println("Shutting down oauth server")
	oas.CtxCancel()
}

func (oas *OAuthServer) callbackGETHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Got callback request")

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	text := fmt.Sprintf("Authorization code is %s\n\nYou can close this window.", code)
	io.WriteString(w, text)

	authResp := AuthorizeResp{Code: code, State: state}
	b, err := json.Marshal(authResp)

	oas.Responses <- common.JsonResponse{Type: "oauth-code", Payload: string(b), Error: err}
}

func (oas *OAuthServer) RedirectUri() string {
	return oas.Origin + RedirectPath
}
