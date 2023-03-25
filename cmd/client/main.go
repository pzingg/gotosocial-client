package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	godebug "runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/frontmatter"
	"github.com/joho/godotenv"
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

// URL path on our server
const redirectPath = "/oauth/callback"

// URL paths on GoToSocial server
const authorizePath = "/oauth/authorize"
const tokenPath = "/oauth/token"
const appsPath = "/api/v1/apps"
const statusPath = "/api/v1/statuses"

// Where to write client secrets and access_token
const secretsFile = "client_secrets.txt"
const tokenFile = "access_token.txt"

var server = make(chan ServerData)

type ServerData struct {
	Msg      string
	Error    string
	JsonData string
}

type AppResp struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Id           string `json:"id"`
	Name         string `json:"name"`
	RedirectURI  string `json:"redirect_uri"`
}

type AuthorizeResp struct {
	State string `json:"state"`
	Code  string `json:"code"`
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

	redirectUri := fmt.Sprintf("http://localhost:%d%s", port, redirectPath)

	m := url.Values{}
	m.Set("client_name", "gtsclient")
	m.Set("redirect_uris", redirectUri)
	m.Set("scopes", scope)
	if website != "" {
		m.Set("website", website)
	}

	appsUrl := instance + appsPath
	d, err := doPost("app", appsUrl, m, "")
	if err != nil {
		return err
	}

	var appResp AppResp
	err = json.Unmarshal([]byte(d.JsonData), &appResp)

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

	go startOAuthServer(port)

	// Wait for server to be up and running
	select {
	case ret := <-server:
		fmt.Printf("Got startup response: %v\n", ret)
	case <-time.After(1 * time.Second):
		fmt.Println("Assuming server has started")
	}

	origin := fmt.Sprintf("http://localhost:%d", port)

	var oauth = OAuth{
		Origin:       origin,
		Instance:     instance,
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Scope:        scope,
		RedirectUri:  origin + redirectPath,
	}

	authorize(&oauth)

	select {
	case d := <-server:
		fmt.Printf("Got auth response: %v\n", d)
		if d.Msg == "oauth-code" {
			if d.JsonData != "" {
				var authResp AuthorizeResp
				err := json.Unmarshal([]byte(d.JsonData), &authResp)

				if err != nil {
					return err
				}

				if authResp.State != oauth.State {
					return errors.New("State mismatch")
				}

				oauth.Code = authResp.Code

				fmt.Println("Fetching token")
				d, err = getToken(&oauth)
				fmt.Printf("Got token response: %v\n", d)

				if err != nil {
					return err
				}

				var tokenResp TokenResp
				err = json.Unmarshal([]byte(d.JsonData), &tokenResp)

				if err != nil {
					return err
				}

				oauth.AccessToken = tokenResp.AccessToken

				fmt.Println("Writing access token")
				line := fmt.Sprintf("Bearer %s\n", oauth.AccessToken)
				_ = os.WriteFile(tokenFile, []byte(line), 0644)
			}
		}
	case <-time.After(120 * time.Second):
		fmt.Println("No response after 10 seconds")
	}
	return err
}

func startOAuthServer(port int) {
	http.HandleFunc("/", rootGETHandler)
	http.HandleFunc(redirectPath, callbackGETHandler)

	addr := fmt.Sprintf(":%d", port)
	var err = http.ListenAndServe(addr, nil)
	if err != nil {
		server <- ServerData{Msg: "started", Error: err.Error()}
	} else {
		m := make(map[string]string)
		m["status"] = "ok"
		b, _ := json.Marshal(m)

		server <- ServerData{Msg: "started", JsonData: string(b)}
	}
}

func rootGETHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Got / request")
	io.WriteString(w, "This is my website!\n")
}

func callbackGETHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Got callback request")

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	text := fmt.Sprintf("Authorization code is %s\n\nYou can close this window.", code)
	io.WriteString(w, text)

	resp := AuthorizeResp{Code: code, State: state}
	b, _ := json.Marshal(resp)

	server <- ServerData{Msg: "oauth-code", JsonData: string(b)}
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

	q := u.Query()
	q.Add("response_type", "code")
	q.Add("state", oauth.State)
	q.Add("client_id", oauth.ClientId)
	q.Add("scope", oauth.Scope)
	q.Add("redirect_uri", oauth.RedirectUri)

	// assign encoded query string to http request
	u.RawQuery = q.Encode()
	err = exec.Command("xdg-open", u.String()).Run()
	return err
}

func getToken(oauth *OAuth) (data ServerData, err error) {
	m := url.Values{}
	m.Set("grant_type", "authorization_code")
	m.Set("state", oauth.State)
	m.Set("code", oauth.Code)
	m.Set("client_id", oauth.ClientId)
	m.Set("client_secret", oauth.ClientSecret)
	m.Set("scope", oauth.Scope)
	m.Set("redirect_uri", oauth.RedirectUri)

	tokenUrl := oauth.Instance + tokenPath
	return doPost("oauth-token", tokenUrl, m, "")
}

func postStatus(ctx context.Context, filename string) (data ServerData, err error) {
	if filename == "" {
		return ServerData{}, errors.New("No filename")
	}
	instance, err := getInstance()
	if err != nil {
		return ServerData{}, err
	}
	authBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return ServerData{}, err
	}
	auth := strings.ReplaceAll(string(authBytes), "\n", "")
	file, err := os.Open(filename)
	if err != nil {
		return ServerData{}, err
	}

	var matter PostFrontMatter
	rest, err := frontmatter.Parse(file, &matter)
	if err != nil {
		return ServerData{}, err
	}

	m := url.Values{}
	m.Set("status", string(rest))
	m.Set("content_type", matter.ContentType)
	m.Set("visibility", matter.Visiblity)

	statusUrl := instance + statusPath
	d, err := doPost("status", statusUrl, m, auth)
	if err != nil {
		return d, err
	}

	fmt.Println("Post succeeded")
	fmt.Println(d.JsonData)
	return d, nil
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

func doPost(label string, url string, m url.Values, auth string) (data ServerData, err error) {
	r, err := http.NewRequest("POST", url, strings.NewReader(m.Encode()))
	if err != nil {
		return ServerData{}, err
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if auth != "" {
		r.Header.Add("Authorization", auth)
	}

	client := &http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		return ServerData{}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Fatalf("Status is %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ServerData{}, err
	}

	data = ServerData{Msg: label, JsonData: string(b)}
	return data, nil
}
