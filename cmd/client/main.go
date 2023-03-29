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
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	godebug "runtime/debug"
	"strings"
	"time"

	"github.com/adrg/frontmatter"
	"github.com/pzingg/gotosocial-client/pkg/common"
	"github.com/pzingg/gotosocial-client/pkg/oauthserver"
	"github.com/pzingg/gotosocial-client/pkg/wsclient"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type OAuth struct {
	Origin       string
	Instance     string
	ClientId     string
	ClientSecret string
	State        string
	Scope        string
	RedirectUri  string
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

type MediaResp struct {
	Id   string `json:"id"`
	Type string `json:"type"`
	Url  string `json:"url"`
}

type MediaParams struct {
	File        string `yaml:"file"`
	Description string `yaml:"description"`
}

type PostFrontMatter struct {
	ContentType string `yaml:"content_type"`
	Visibility  string `yaml:"visibility"`
	Attachments []MediaParams
}

// Version is the version being used.
// It's injected into the binary by the build script.
var Version string

// URL paths on GoToSocial server
const authorizePath = "/oauth/authorize"
const tokenPath = "/oauth/token"
const appsPath = "/api/v1/apps"
const statusPath = "/api/v1/statuses"
const mediaPath = "/api/v1/media"
const streamingPath = "/api/v1/streaming"

// Where to write client secrets and access token
const secretsFile = "client_secrets.txt"
const tokenFile = "access_token.txt"

// Global configuration
var config *viper.Viper

func main() {
	var instanceUrl string
	var serverPort int
	var scope string
	var appName string
	var website string
	var clientId string
	var clientSecret string
	var statusFile string
	var streamType string

	version := version()

	// instantiate the root command
	rootCmd := &cobra.Command{
		Use:           "client",
		Short:         "GoToSocial Client - tools for logging in and posting to GoToSocial",
		Version:       version,
		SilenceErrors: true,
		SilenceUsage:  false,
	}

	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Register a client app on gotosocial",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return loadConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return registerApp(cmd.Context(), args)
		},
	}
	registerCmd.Flags().StringVarP(&instanceUrl, "instance_url", "i", "",
		"GoToSocial instance URL")
	registerCmd.Flags().IntVarP(&serverPort, "server_port", "p", 4040,
		"Port on localhost to bind callback server")
	registerCmd.Flags().StringVarP(&scope, "scope", "s", "read write follow push",
		"Permissions")
	registerCmd.Flags().StringVarP(&appName, "app_name", "n", "GtsClient",
		"Name of app you are registering")
	registerCmd.Flags().StringVarP(&website, "website", "w", "",
		"Optional website name to register")
	rootCmd.AddCommand(registerCmd)

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Login to gotosocial using OAuth2 in a browser",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return loadConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return login(cmd.Context(), args)
		},
	}
	loginCmd.Flags().StringVarP(&instanceUrl, "instance_url", "i", "",
		"GoToSocial instance URL")
	loginCmd.Flags().IntVarP(&serverPort, "server_port", "p", 4040,
		"Port on localhost to bind callback server")
	loginCmd.Flags().StringVarP(&scope, "scope", "s", "read write follow push",
		"Permissions")
	loginCmd.Flags().StringVarP(&clientId, "client_id", "", "",
		"Client ID")
	loginCmd.Flags().StringVarP(&clientSecret, "client_secret", "", "",
		"Client secret")
	rootCmd.AddCommand(loginCmd)

	postCmd := &cobra.Command{
		Use:   "post",
		Short: "Post a status to gotosocial",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return loadConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return postStatus(cmd.Context(), args)
		},
	}
	postCmd.Flags().StringVarP(&instanceUrl, "instance_url", "i", "",
		"GoToSocial instance URL")
	postCmd.Flags().StringVarP(&statusFile, "status_file", "f", "status.md",
		"Markdown file to post")
	rootCmd.AddCommand(postCmd)

	streamCmd := &cobra.Command{
		Use:   "stream",
		Short: "Listen for streaming from a gotosocial server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return loadConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return stream(cmd.Context(), args)
		},
	}
	streamCmd.Flags().StringVarP(&streamType, "stream_type", "t", "user",
		"Stream type: user, public, direct, list, hashtag")
	rootCmd.AddCommand(streamCmd)

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
	if config == nil {
		log.Panicln("no config")
	}
	instance := config.GetString("instance_url")
	if instance == "" {
		return errors.New("missing instance_url")
	}
	port := config.GetInt("server_port")
	if port == 0 {
		return errors.New("missing server_port")
	}
	name := config.GetString("app_name")
	if name == "" {
		return errors.New("missing app_name")
	}
	scope := config.GetString("scope")
	if scope == "" {
		return errors.New("missing scope")
	}
	// website is optional
	website := config.GetString("website")
	redirectUri := fmt.Sprintf("http://localhost:%d%s", port, oauthserver.RedirectPath)

	m := url.Values{}
	m.Set("client_name", "gtsclient")
	m.Set("redirect_uris", redirectUri)
	m.Set("scopes", scope)
	if website != "" {
		m.Set("website", website)
	}

	jsonResp, err := httpPost("app", instance+appsPath, m, "")
	if err != nil {
		return err
	}
	if jsonResp.Error != nil {
		return jsonResp.Error
	}

	var appResp AppResp
	err = json.Unmarshal([]byte(jsonResp.Payload), &appResp)

	log.Println("Writing client secrets")
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

	log.Printf("Copy your secrets from %s into .env file!\n", secretsFile)
	return nil
}

func login(ctx context.Context, args []string) (err error) {
	if config == nil {
		log.Panicln("no config")
	}
	instance := config.GetString("instance_url")
	if instance == "" {
		return errors.New("missing instance_url")
	}
	port := config.GetInt("server_port")
	if port == 0 {
		return errors.New("missing server_port")
	}
	scope := config.GetString("scope")
	if scope == "" {
		return errors.New("missing scope")
	}
	clientId := config.GetString("client_id")
	if clientId == "" {
		return errors.New("missing client_id")
	}
	clientSecret := config.GetString("client_secret")
	if clientSecret == "" {
		return errors.New("missing client_secret")
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

	err = oauth.launchBrowser()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for ; ; <-ticker.C {
		select {
		case <-oas.Ctx.Done():
			log.Println("Received server done. Goodbye")
			return nil
		case jsonResp := <-oas.Responses:
			log.Printf("Received %s response\n", jsonResp.Type)
			if jsonResp.Type == "oauth-code" {
				if jsonResp.Error != nil {
					log.Printf("Error in oauth-code: %s\n", jsonResp.Error)
					return jsonResp.Error
				}

				var authResp oauthserver.AuthorizeResp
				err = json.Unmarshal([]byte(jsonResp.Payload), &authResp)
				if err != nil {
					return err
				}
				if authResp.State != oauth.State {
					return errors.New("state mismatch")
				}

				log.Println("Fetching token")
				jsonResp, err := oauth.getTokenResponse(authResp.Code)
				if err != nil {
					return err
				}
				if jsonResp.Error != nil {
					return jsonResp.Error
				}

				log.Println("Got token response")
				var tokenResp TokenResp
				err = json.Unmarshal([]byte(jsonResp.Payload), &tokenResp)
				if err != nil {
					return err
				}

				log.Println("Writing access token and stopping server")
				line := tokenResp.AccessToken + "\n"
				_ = os.WriteFile(tokenFile, []byte(line), 0644)
				oas.Shutdown()
				return nil
			}
		default:

		}
	}
}

func (oauth *OAuth) launchBrowser() error {
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

	return exec.Command("xdg-open", u.String()).Run()
}

func (oauth *OAuth) getTokenResponse(code string) (data *common.JsonResponse, err error) {
	m := url.Values{}
	m.Set("grant_type", "authorization_code")
	m.Set("code", code)
	m.Set("state", oauth.State)
	m.Set("client_id", oauth.ClientId)
	m.Set("client_secret", oauth.ClientSecret)
	m.Set("scope", oauth.Scope)
	m.Set("redirect_uri", oauth.RedirectUri)

	return httpPost("oauth-token", oauth.Instance+tokenPath, m, "")
}

func postStatus(ctx context.Context, args []string) (err error) {
	if config == nil {
		log.Panicln("no config")
	}
	instance := config.GetString("instance_url")
	if instance == "" {
		return errors.New("missing instance_url")
	}
	statusFile := config.GetString("status_file")
	if statusFile == "" {
		return errors.New("missing status_file")
	}
	token, err := getToken(tokenFile)
	if err != nil {
		return err
	}
	file, err := os.Open(statusFile)
	if err != nil {
		return err
	}

	var meta PostFrontMatter
	rest, err := frontmatter.Parse(file, &meta)
	if err != nil {
		return err
	}

	var mediaIds []string
	if len(meta.Attachments) > 0 {
		mediaIds, err = uploadMedia("attachments", meta.Attachments, instance+mediaPath, token)
		if err != nil {
			return err
		}
	}

	m := url.Values{}
	m.Set("status", string(rest))
	m.Set("content_type", meta.ContentType)
	m.Set("visibility", meta.Visibility)
	for _, mediaId := range mediaIds {
		m.Add("media_ids[]", mediaId)
	}

	jsonResp, err := httpPost("post", instance+statusPath, m, "Bearer "+token)
	if err != nil {
		return err
	}
	if jsonResp.Error != nil {
		return jsonResp.Error
	}

	log.Println("Post succeeded")
	prettyPrint(jsonResp.Payload, 2)
	return nil
}

func uploadMedia(label string, files []MediaParams, url string, token string) (mediaIds []string, err error) {
	auth := "Bearer " + token
	mediaIds = make([]string, len(files))

	for index, params := range files {
		jsonResp, err := uploadOne(label, params, url, auth)
		if err != nil {
			return nil, err
		}
		if jsonResp.Error != nil {
			return nil, jsonResp.Error
		}

		var mediaResp MediaResp
		err = json.Unmarshal([]byte(jsonResp.Payload), &mediaResp)
		if err != nil {
			return nil, err
		}
		mediaIds[index] = mediaResp.Id
	}

	return mediaIds, nil
}

func uploadOne(label string, params MediaParams, url string, auth string) (data *common.JsonResponse, err error) {
	contents, err := os.ReadFile(params.File)
	if err != nil {
		return nil, err
	}
	var (
		buf = new(bytes.Buffer)
		w   = multipart.NewWriter(buf)
	)
	err = w.WriteField("api_version", "v1")
	if err != nil {
		return nil, err
	}
	err = w.WriteField("description", params.Description)
	if err != nil {
		return nil, err
	}
	part, err := w.CreateFormFile("file", filepath.Base(params.File))
	if err != nil {
		return nil, err
	}
	_, err = part.Write(contents)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequest("POST", url, buf)
	if err != nil {
		return nil, err
	}
	r.Header.Add("Content-Type", w.FormDataContentType())
	if auth != "" {
		r.Header.Add("Authorization", auth)
	}
	return httpRequest(label, r)
}

func stream(ctx context.Context, args []string) error {
	if config == nil {
		log.Panicln("no config")
	}
	instance := config.GetString("instance_url")
	if instance == "" {
		return errors.New("missing instance_url")
	}
	streamType := config.GetString("stream_type")
	if streamType == "" {
		return errors.New("missing stream_type")
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

	// GoToSocial stream connection requires ws or wss connection URL
	if u.Scheme == "http" {
		u.Scheme = "ws"
	} else {
		u.Scheme = "wss"
	}
	// Required query string
	q := url.Values{}
	q.Set("access_token", token)
	q.Set("stream", streamType)
	u.RawQuery = q.Encode()

	messages := make(chan wsclient.GtsMessage, 1)
	wsClient := wsclient.NewWebSocketClient(ctx, u.String(), messages)

	// Send subscribe message to open stream
	m := make(map[string]string)
	m["type"] = "subscribe"
	m["stream"] = streamType
	err = wsClient.Write(m)
	if err != nil {
		log.Println("Stream write failed, stopping")
		wsClient.Stop()
		return err
	}

	log.Println("Waiting for messages on stream")
	var message wsclient.GtsMessage
	for {
		select {
		case <-wsClient.Ctx.Done():
			log.Println("Received socket done. Goodbye")
			return nil
		case message = <-messages:
			log.Printf("Received message for %v: %s\n", message.Stream, message.Event)
			prettyPrint(message.Payload, 2)
		default:
			// spin spin spin
		}
	}
}

func loadConfig(cmd *cobra.Command) error {
	v := viper.New()
	v.AddConfigPath(".")
	v.SetConfigName("local")
	v.SetConfigType("env")
	v.AutomaticEnv()

	err := v.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}

		// It's okay if there isn't a config file
		log.Println("No local.env config file read")
	}

	// Merge cmd flags on top of environment settings, and set global config
	config = bindFlags(cmd, v)

	return nil
}

// Bind each cobra flag to its associated viper configuration
// (config file and environment variable)
func bindFlags(cmd *cobra.Command, v *viper.Viper) *viper.Viper {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		key := f.Name
		if key != "help" && (f.Changed || !v.IsSet(key)) {
			v.BindPFlag(key, f)
		}
	})
	return v
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
	r, err := http.NewRequest("GET", url, nil)
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
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	jsonResp := &common.JsonResponse{Type: label, Payload: string(b)}
	if resp.StatusCode >= 300 {
		jsonResp.Error = &common.HttpResponseError{Type: label, StatusCode: resp.StatusCode}
	}
	return jsonResp, nil
}

func prettyPrint(payload string, indent int) error {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, []byte(payload), "", strings.Repeat(" ", indent))
	if err != nil {
		return err
	}
	log.Println(string(prettyJSON.Bytes()))
	return nil
}
