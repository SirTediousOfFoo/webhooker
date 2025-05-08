package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
)

// GitHubWebhookPayload has the payload structure for GitHub webhook events.
type GitHubWebhookPayload struct {
	Action string `json:"action"`
	// Add other fields as needed based on the GitHub event type.
}

// Config structure for the configuration file.
type Config struct {
	Destination string `yaml:"destination"`
	Source      string `yaml:"source"`
	Secret      string `yaml:"secret"`
}

// Set the config variable to the global scope for easier access
var config Config

func init() {
	// Read the config file
	configPath := "/etc/webhooker/config.yaml"
	configFile, err := os.Open(configPath)

	if err != nil {
		log.Fatalf("Error opening config file: %s", err)
	}
	defer configFile.Close()
	var config Config
	decoder := yaml.NewDecoder(configFile)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Error decoding config file: %s", err)
	}
}

func syncWithRepo(config Config) {
	// Position git in the directory set in the config
	err := exec.Command("git", "-C", config.Source).Run()
	if err != nil {
		log.Printf("Error changing directory: %s\nSync it manually this time? ¯\\_(ツ)_/¯", err)
		return
	}
	// Let's do the manual work here now, first fetch the latest changes
	exec.Command("git", "-C", config.Source, "fetch", "--all").Run()
	// Then pull the latest changes
	exec.Command("git", "-C", config.Source, "pull").Run()
	// Cool, now we can copy the files to the destination
	exec.Command("cp", "-r", config.Source+"/*", config.Destination).Run()
	// Now reload the webserver and we're all done unless something broke apart
	exec.Command("systemctl", "reload", "apache2.service").Run()
}

func validateWebhook(body []byte, hookSignature string) bool {
	// Simple validation logic
	key := []byte(config.Secret)

	signature := hmac.New(sha256.New, key)
	signature.Write(body)
	expectedSignature := hex.EncodeToString(signature.Sum(nil))

	return hmac.Equal([]byte(hookSignature[7:]), []byte(expectedSignature))
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	// Validate the webhook signature
	if validateWebhook(body, r.Header.Get("X-Hub-Signature-256")) == false {
		http.Error(w, "Invalid webhook signature", http.StatusUnauthorized)
		return
	}
	defer r.Body.Close()

	var payload GitHubWebhookPayload
	err = json.Unmarshal(body, &payload)
	if err != nil {
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}


	log.Printf("Received webhook action: %s\n", payload.Action)

	// Example: Execute Linux commands based on the webhook action
	if payload.Action == "push" {
		syncWithRepo(config)
	} else if payload.Action == "ping" {
		log.Printf("Ping event received")
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Webhook received"))
}

func main() {
	http.HandleFunc("/webhook", webhookHandler)

	port := "23454"
	log.Printf("Listening on port %s...\n", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Printf("Error starting server: %s\n", err)
	}
}
