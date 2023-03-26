package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/pzingg/gotosocial-client/pkg/common"
)

type OAuthServer struct {
	httpServer *http.Server
	Ctx        context.Context
	CtxCancel  context.CancelFunc
	Origin     string
	Responses  chan common.JsonResponse
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
	oas.Ctx, oas.CtxCancel = context.WithCancel(ctx)

	router := mux.NewRouter()
	router.HandleFunc(RedirectPath, oas.callbackGETHandler)
	oas.httpServer = &http.Server{Addr: addr, Handler: router}

	go oas.start()
	return oas
}

func (oas *OAuthServer) RedirectUri() string {
	return oas.Origin + RedirectPath
}

func (oas *OAuthServer) start() {
	log.Println("Starting oauth server")
	if err := oas.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	} else {
		log.Println("Oauth server stopped gracefully")
	}
}

func (oas *OAuthServer) Shutdown() {
	log.Println("Shutting down oauth server")
	oas.CtxCancel()
}

func (oas *OAuthServer) callbackGETHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Got callback request")

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	text := fmt.Sprintf("Authorization code is %s\n\nYou can close this window.", code)
	io.WriteString(w, text)

	resp := AuthorizeResp{Code: code, State: state}
	b, _ := json.Marshal(resp)

	oas.Responses <- common.JsonResponse{Type: "oauth-code", Payload: string(b)}
}
