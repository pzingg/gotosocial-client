package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	godebug "runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/adrg/frontmatter"
	"github.com/joho/godotenv"
	"github.com/pzingg/gotosocial-client/pkg/common"
	"github.com/pzingg/gotosocial-client/pkg/oauthserver"
	"github.com/pzingg/gotosocial-client/pkg/wsclient"
	"github.com/spf13/cobra"
)

type OAuth struct {
	Origin       string
	Instance     string
	ClientId     string
	ClientSecret string
	State        string
	Scope        string
	RedirectUri  string
	Code         string
	AccessToken  string
}

type AppResp struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Id           string `json:"id"`
	Name         string `json:"name"`
	RedirectURI  string `json:"redirect_uri"`
}

type TokenResp struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	CreatedAt   int    `json:"created_at"`
}

type PostFrontMatter struct {
	ContentType string `yaml:"content_type"`
	Visiblity   string `yaml:"visibility"`
}

// Version is the version being used.
// It's injected into the binary by the build script.
var Version string

// URL paths on GoToSocial server
const authorizePath = "/oauth/authorize"
const tokenPath = "/oauth/token"
const appsPath = "/api/v1/apps"
const statusPath = "/api/v1/statuses"
const streamingPath = "/api/v1/streaming"

// Where to write client secrets and access_token
const secretsFile = "client_secrets.txt"
const tokenFile = "access_token.txt"

// Close connection correctly on exit
var sigs = make(chan os.Signal, 1)

func main() {
	version := version()

	err := godotenv.Load()
	if err != nil {
		fmt.Println(".env file not loaded")
	}

	// instantiate the root command
	rootCmd := &cobra.Command{
		Use:           "client",
		Short:         "GoToSocial Client - tools for logging in and posting to GoToSocial",
		Version:       version,
		SilenceErrors: false,
		SilenceUsage:  false,
	}

	registerCommand := &cobra.Command{
		Use:   "register",
		Short: "Register a client app on gotosocial",
		RunE: func(cmd *cobra.Command, args []string) error {
			return registerApp(cmd.Context(), args)
		},
	}
	rootCmd.AddCommand(registerCommand)

	loginCommand := &cobra.Command{
		Use:   "login",
		Short: "Login to gotosocial using OAuth2 in a browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			return login(cmd.Context(), args)
		},
	}
	rootCmd.AddCommand(loginCommand)

	var statusFile string
	postCommand := &cobra.Command{
		Use:   "post",
		Short: "Post a status to gotosocial",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := postStatus(cmd.Context(), statusFile)
			return err
		},
	}
	postCommand.Flags().StringVarP(&statusFile, "file", "f", "status.md", "Markdown file to post")
	rootCmd.AddCommand(postCommand)

	var streamType string
	streamCommand := &cobra.Command{
		Use:   "stream",
		Short: "Listen for streaming from a gotosocial server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return stream(cmd.Context(), streamType)
		},
	}
	streamCommand.Flags().StringVarP(&streamType, "type", "t", "public", "Stream type: user, public, direct, list, hashtag")
	rootCmd.AddCommand(streamCommand)

	// `signal.Notify` registers the given channel to
	// receive notifications of the specified signals.
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// run
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("error executing command: %s", err)
	}
}

// version will build a version string from binary's stored build information.
func version() string {
	// Read build information from binary
	build, ok := godebug.ReadBuildInfo()
	if !ok {
		return ""
	}

	// Define easy getter to fetch build settings
	getSetting := func(key string) string {
		for i := 0; i < len(build.Settings); i++ {
			if build.Settings[i].Key == key {
				return build.Settings[i].Value
			}
		}
		return ""
	}

	var info []string

	if Version != "" {
		// Append version if set
		info = append(info, Version)
	}

	if vcs := getSetting("vcs"); vcs != "" {
		// A VCS type was set (99.9% probably git)

		if commit := getSetting("vcs.revision"); commit != "" {
			if len(commit) > 7 {
				// Truncate commit
				commit = commit[:7]
			}

			// Append VCS + commit if set
			info = append(info, vcs+"-"+commit)
		}
	}

	return strings.Join(info, " ")
}

func registerApp(ctx context.Context, args []string) error {
	port, err := getPort()
	if err != nil {
		return err
	}
	instance, err := getInstance()
	if err != nil {
		return err
	}
	scope, err := getScope()
	if err != nil {
		return err
	}
	website, _ := os.LookupEnv("WEBSITE")

	redirectUri := fmt.Sprintf("http://localhost:%d%s", port, oauthserver.RedirectPath)

	m := url.Values{}
	m.Set("client_name", "gtsclient")
	m.Set("redirect_uris", redirectUri)
	m.Set("scopes", scope)
	if website != "" {
		m.Set("website", website)
	}

	appsUrl := instance + appsPath
	d, err := httpPost("app", appsUrl, m, "")
	if err != nil {
		return err
	}

	var appResp AppResp
	err = json.Unmarshal([]byte(d.Payload), &appResp)

	fmt.Println("Writing client secrets")
	content := fmt.Sprintf("CLIENT_ID=\"%s\"\nCLIENT_SECRET=\"%s\"\nREDIRECT_URI=\"%s\"\nAPP_ID=\"%s\"\nAPP_NAME=\"%s\"\n",
		appResp.ClientId,
		appResp.ClientSecret,
		appResp.RedirectURI,
		appResp.Id,
		appResp.Name)
	err = os.WriteFile(secretsFile, []byte(content), 0644)

	if err != nil {
		return err
	}

	fmt.Printf("Copy your secrets from %s into .env file!\n", secretsFile)
	return nil
}

func login(ctx context.Context, args []string) error {
	port, err := getPort()
	if err != nil {
		return err
	}
	instance, err := getInstance()
	if err != nil {
		return err
	}
	scope, err := getScope()
	if err != nil {
		return err
	}
	clientId, clientSecret, err := getSecrets()
	if err != nil {
		return err
	}

	oas := oauthserver.NewOAuthServer(ctx, port)
	oauth := &OAuth{
		Origin:       oas.Origin,
		Instance:     instance,
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Scope:        scope,
		RedirectUri:  oas.RedirectUri(),
	}

	authorize(oauth)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ; ; <-ticker.C {
		select {
		case <-sigs:
			oas.Shutdown()
			return nil
		case <-oas.Ctx.Done():
			return nil
		case d := <-oas.Responses:
			fmt.Printf("Got auth response: %v\n", d)
			if d.Msg == "oauth-code" {
				if d.Payload != "" {
					var authResp oauthserver.AuthorizeResp
					err := json.Unmarshal([]byte(d.Payload), &authResp)

					if err != nil {
						return err
					}

					if authResp.State != oauth.State {
						return errors.New("State mismatch")
					}

					oauth.Code = authResp.Code

					fmt.Println("Fetching token")
					tokenData, err := getTokenResponse(oauth)
					fmt.Printf("Got token response: %v\n", d)

					if err != nil {
						return err
					}

					var tokenResp TokenResp
					err = json.Unmarshal([]byte(tokenData.Payload), &tokenResp)

					if err != nil {
						return err
					}

					oauth.AccessToken = tokenResp.AccessToken

					fmt.Println("Writing access token")
					line := oauth.AccessToken + "\n"
					_ = os.WriteFile(tokenFile, []byte(line), 0644)
				}
			}
		default:

		}
	}
	return err
}

func authorize(oauth *OAuth) (err error) {
	buf := make([]byte, 32)
	rand.Read(buf)
	oauth.State = fmt.Sprintf("%x", buf)

	authorizeUrl := oauth.Instance + authorizePath
	u, err := url.Parse(authorizeUrl)
	if err != nil {
		return err
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("state", oauth.State)
	q.Set("client_id", oauth.ClientId)
	q.Set("scope", oauth.Scope)
	q.Set("redirect_uri", oauth.RedirectUri)
	u.RawQuery = q.Encode()

	err = exec.Command("xdg-open", u.String()).Run()
	return err
}

func getTokenResponse(oauth *OAuth) (data *common.JsonResponse, err error) {
	m := url.Values{}
	m.Set("grant_type", "authorization_code")
	m.Set("state", oauth.State)
	m.Set("code", oauth.Code)
	m.Set("client_id", oauth.ClientId)
	m.Set("client_secret", oauth.ClientSecret)
	m.Set("scope", oauth.Scope)
	m.Set("redirect_uri", oauth.RedirectUri)

	tokenUrl := oauth.Instance + tokenPath
	return httpPost("oauth-token", tokenUrl, m, "")
}

func postStatus(ctx context.Context, filename string) (data *common.JsonResponse, err error) {
	if filename == "" {
		return nil, errors.New("No filename")
	}
	instance, err := getInstance()
	if err != nil {
		return nil, err
	}
	token, err := getToken(tokenFile)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	var matter PostFrontMatter
	rest, err := frontmatter.Parse(file, &matter)
	if err != nil {
		return nil, err
	}

	m := url.Values{}
	m.Set("status", string(rest))
	m.Set("content_type", matter.ContentType)
	m.Set("visibility", matter.Visiblity)

	statusUrl := instance + statusPath
	auth := "Bearer " + token
	d, err := httpPost("status", statusUrl, m, auth)
	if err != nil {
		return d, err
	}

	fmt.Println("Post succeeded")
	prettyPrint(d.Payload, 2)
	return d, nil
}

func stream(ctx context.Context, streamType string) error {
	instance, err := getInstance()
	if err != nil {
		return err
	}
	token, err := getToken(tokenFile)
	if err != nil {
		return err
	}

	streamingUrl := instance + streamingPath
	u, err := url.Parse(streamingUrl)
	if err != nil {
		return err
	}

	/* u.Scheme = "wss" */
	u.Scheme = "ws"
	q := url.Values{}
	q.Set("access_token", token)
	q.Set("stream", streamType)
	u.RawQuery = q.Encode()

	messages := make(chan wsclient.GtsMessage, 1)
	wsClient := wsclient.NewWebSocketClient(ctx, u.String(), messages)

	m := make(map[string]string)
	m["type"] = "subscribe"
	m["stream"] = streamType
	err = wsClient.Write(m)
	if err != nil {
		fmt.Println("Write failed, stopping")
		wsClient.Stop()
		return err
	}

	fmt.Println("Waiting for messages on stream")
	var message wsclient.GtsMessage
	for {
		select {
		case message = <-messages:
			fmt.Printf("Received message for %v: %s\n", message.Stream, message.Event)
			prettyPrint(message.Payload, 2)
		case <-sigs:
			fmt.Println("Received signal. Stopping")
			wsClient.Stop()
			return nil
		case <-wsClient.Ctx.Done():
			fmt.Println("Received socket done. Goodbye")
			return nil
		default:

		}
		// spin spin spin
	}
}

func getInstance() (instance string, err error) {
	instance, ok := os.LookupEnv("INSTANCE_URL")
	if !ok {
		return "", errors.New("missing INSTANCE_URL")
	}
	return instance, nil
}

func getPort() (port int, err error) {
	serverPort, ok := os.LookupEnv("SERVER_PORT")
	if !ok {
		return 0, errors.New("missing SERVER_PORT")
	}
	port, err = strconv.Atoi(serverPort)
	return port, err
}

func getScope() (scope string, err error) {
	scope, ok := os.LookupEnv("SCOPE")
	if !ok {
		return "", errors.New("missing SCOPE")
	}
	return scope, nil
}

func getSecrets() (clientId string, clientSecret string, err error) {
	clientId, ok := os.LookupEnv("CLIENT_ID")
	if !ok {
		return "", "", errors.New("missing CLIENT_ID")
	}
	clientSecret, ok = os.LookupEnv("CLIENT_SECRET")
	if !ok {
		return "", "", errors.New("missing CLIENT_SECRET")
	}
	return clientId, clientSecret, nil
}

func getToken(filename string) (string, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	token := strings.ReplaceAll(string(b), "\n", "")
	return token, nil
}

func httpGet(label string, url string) (data *common.JsonResponse, err error) {
	r, err := http.NewRequest("GET", url, strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	return httpRequest(label, r)
}

func httpPost(label string, url string, m url.Values, auth string) (data *common.JsonResponse, err error) {
	r, err := http.NewRequest("POST", url, strings.NewReader(m.Encode()))
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if auth != "" {
		r.Header.Add("Authorization", auth)
	}
	return httpRequest(label, r)
}

func httpRequest(label string, r *http.Request) (data *common.JsonResponse, err error) {
	client := &http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	d := &common.JsonResponse{Type: label}
	if resp.StatusCode >= 300 {
		d.Error = fmt.Sprintf("Status %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	d.Payload = string(b)
	return d, nil
}

func prettyPrint(payload string, indent int) error {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, []byte(payload), "", strings.Repeat(" ", indent))
	if err != nil {
		return err
	}
	fmt.Println(string(prettyJSON.Bytes()))
	return nil
}
