package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	webexteams "github.com/jbogarin/go-cisco-webex-teams/sdk"
	resty "gopkg.in/resty.v1"
)

type dogapi struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

//WebhookData - For Incoming Webhooks
type WebhookData struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	TargetURL string `json:"targetUrl"`
	Resource  string `json:"resource"`
	Event     string `json:"event"`
	OrgID     string `json:"orgId"`
	CreatedBy string `json:"createdBy"`
	AppID     string `json:"appId"`
	OwnedBy   string `json:"ownedBy"`
	Status    string `json:"status"`
	Created   string `json:"created"`
	ActorID   string `json:"actorId"`
	Data      *Data
}

//Data - Data field in WebhookData
type Data struct {
	ID          string `json:"id"`
	RoomID      string `json:"roomId"`
	RoomType    string `json:"roomType"`
	PersonID    string `json:"personId"`
	PersonEmail string `json:"personEmail"`
	Created     string `json:"created"`
}

var webexClient *webexteams.Client

//SecretStr - For HMAC SHA1 Verification
var SecretStr string

//Port - For Heroku Port
var Port string
var publicURL string

//InitWebexClient - Setup Token for webexClient
func InitWebexClient() {

	token := os.Getenv("WEBEX_TOKEN")
	publicURL = os.Getenv("PUBLIC_URL")
	if len(token) < 1 || len(publicURL) < 1 {
		log.Fatal("Environmental variables not set!")
		os.Exit(0)
	}
	client := resty.New()
	client.SetAuthToken(token)
	webexClient = webexteams.NewClient(client)

	//Verifying Token
	bot, _, err := webexClient.People.GetMe()
	if err != nil || bot.PersonType != "bot" {
		log.Fatal("Token Invalid or doesn't belong to a bot. Exiting!")
		os.Exit(1)
	}
	fmt.Println("Logged in.")

	//Webhook Registration

	//Delete existing webhooks first to prevent Redundancy
	DeleteAllHooks()

	//CREATE NEW WEBHOOKS HERE
	fmt.Println("Registering new Webhook(s)...")
	webhookRequest := &webexteams.WebhookCreateRequest{
		Name:      "messages created",
		TargetURL: publicURL,
		Resource:  "messages",
		Event:     "created",
		Secret:    SecretStr,
	}

	_, _, err = webexClient.Webhooks.CreateWebhook(webhookRequest)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Webhook Registration Successful!")
	}

}

//DeleteAllHooks - Deleting all the existing webhooks for the bot
func DeleteAllHooks() {
	webhooks, _, err := webexClient.Webhooks.ListWebhooks(&webexteams.ListWebhooksQueryParams{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(strconv.Itoa(len(webhooks.Items)) + " existing Webhook(s) found! Deleting All...")
	for _, webhook := range webhooks.Items {
		_, err := webexClient.Webhooks.DeleteWebhook(webhook.ID)
		if err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println("Deletion Successful!")
}

//RandomString - Generate Random String of length n
func RandomString(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	output := make([]byte, n)
	randomness := make([]byte, n)
	_, err := rand.Read(randomness)
	if err != nil {
		panic(err)
	}
	l := len(letterBytes)
	// fill output
	for pos := range output {
		// get random item
		random := uint8(randomness[pos])
		// random % 64
		randomPos := random % uint8(l)
		// put into output
		output[pos] = letterBytes[randomPos]
	}
	return string(output)
}

func getDog(hookData WebhookData) *webexteams.MessageCreateRequest {

	message := &webexteams.MessageCreateRequest{
		Text:   "Something Went Wrong! Try again later. Woof!",
		RoomID: hookData.Data.RoomID,
	}

	resp, err := http.Get("https://dog.ceo/api/breeds/image/random")
	if err != nil {
		return message
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if err != nil {
		return message
	}

	var apiresp dogapi

	json.Unmarshal(body, &apiresp)

	if apiresp.Status != "success" {
		return message
	}

	var files []string
	files = append(files, apiresp.Message)

	message = &webexteams.MessageCreateRequest{
		Files:  files,
		RoomID: hookData.Data.RoomID,
	}
	return message
}

//ProcessWebhook - Process a valid webhook received
func ProcessWebhook(w http.ResponseWriter, hookData WebhookData) {
	json.NewEncoder(w).Encode("Webhook Received!")
	message := getDog(hookData)

	//Send the Response back to WebexClient
	_, _, err := webexClient.Messages.CreateMessage(message)
	if err != nil {
		log.Fatal(err)
	}
}

//HandleGet - To answer ping calls
func HandleGet(w http.ResponseWriter, r *http.Request) {

	w.Write([]byte("Bot is up and running! Make sure to register the Webhooks before using the bot!"))

}

//IsValidSender - Verify secret
func IsValidSender(body, ExpectedMAC []byte) bool {
	mac := hmac.New(sha1.New, []byte(SecretStr))
	mac.Write(body)
	UnformattedMAC := mac.Sum(nil)
	FormattedMAC := []byte(fmt.Sprintf("%x", UnformattedMAC))
	return hmac.Equal(FormattedMAC, ExpectedMAC)
}

//HandlePost - To handle the incoming webhooks
func HandlePost(w http.ResponseWriter, r *http.Request) {

	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		log.Fatal(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Error reading Request Body!"))
		return
	}

	var receivedHook WebhookData
	json.Unmarshal(b, &receivedHook)

	//X-Spark-Signature doesn't match or Sender is a bot
	sender := receivedHook.Data.PersonEmail
	if !IsValidSender(b, []byte(r.Header.Get("X-Spark-Signature"))) || sender[strings.Index(sender, "@"):] == "@webex.bot" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized Access"))
		return
	}

	//Process Webhook Request
	ProcessWebhook(w, receivedHook)

}

func keepAwake() {
	for {
		time.Sleep(time.Minute * 25)
		_, _ = http.Get(publicURL)
	}
}

func main() {

	//Generate Webhook Secret
	SecretStr = RandomString(16)
	Port = os.Getenv("PORT")

	//Initialize Webex Client
	InitWebexClient()

	//Init router
	router := mux.NewRouter()

	//Handle routes/Endpoints
	router.HandleFunc("/", HandleGet).Methods("GET")
	router.HandleFunc("/", HandlePost).Methods("POST")

	//Starting the Server
	fmt.Println("Starting the Server on Port", Port)
	go keepAwake()
	log.Fatal(http.ListenAndServe(":"+Port, router))

}
