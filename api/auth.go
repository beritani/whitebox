package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/beritani/whitebox/client"
	"github.com/beritani/whitebox/core"
	"github.com/tyler-smith/go-bip39"
)

// Session ...
type Session struct {
	ID string `json:"id"`
}

// Register ...
type Register struct {
	Mnemonic string `json:"mnemonic"`
}

func login(w http.ResponseWriter, r *http.Request) {
	mnemonic := r.FormValue("mnemonic")
	password := r.FormValue("password")

	if mnemonic == "" {
		http.Error(w, "Invalid mnemonic", http.StatusBadRequest)
		return
	}

	handlers := GetLocalHandlers(envData)
	client, err := client.NewClient(mnemonic, password, int(envSize), handlers)
	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientID := client.ID()
	clients[clientID] = &Client{
		Client: client,
		mutex:  &sync.Mutex{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Session{ID: client.ID()})
}

func logout(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-Id")
	delete(clients, sessionID)
}

func register(w http.ResponseWriter, r *http.Request) {
	mnemonic, err := core.GetMnemonic()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Register{Mnemonic: mnemonic})
}

func wordlist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bip39.GetWordList())
}

func verify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("X-Session-Id")
		if _, ok := clients[sessionID]; ok {
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Unauthorised access", http.StatusUnauthorized)
		}
	})
}