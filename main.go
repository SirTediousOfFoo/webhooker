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
	decoder := yaml.NewDecoder(configFile)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Error decoding config file: %s", err)
	}
}

func syncWithRepo() {
	// Let's do the manual work here now, first fetch the latest changes
	err := exec.Command("git", "-C", config.Source, "fetch", "--all").Run()
	if err != nil {
		log.Printf("Error fetching changes: %s\n", err)
		return
	}
	// Then pull the latest changes
	err = exec.Command("git", "-C", config.Source, "pull").Run()
		if err != nil {
		log.Printf("Error pulling : %s\n", err)
		return
	}
	// Cool, now we can copy the files to the destination
	err = exec.Command("cp", "-r", config.Source+"/*", config.Destination).Run()
	if err != nil {
		log.Printf("Error copying files: %s\n", err)
		return
	}
	// Now reload the webserver and we're all done unless something broke apart
	err = exec.Command("systemctl", "reload", "apache2.service").Run()
	if err != nil {

		log.Printf("Error reloading apache2: %s\n", err)
		return
	}
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
	action := r.Header.Get("X-GitHub-Event")
	log.Printf("Received webhook action: %s\n", action)
	// Example: Execute Linux commands based on the webhook action
	if action == "push" {
		syncWithRepo()
	} else if action == "ping" {
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
