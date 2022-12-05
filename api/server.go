package api

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/beritani/whitebox/client"
	"github.com/gorilla/mux"
)

var (
	envHost string
	envPort string
	envData string
	envSize int
	clients  map[string]*Client
)

// Client ...
type Client struct {
	*client.Client
	mutex *sync.Mutex
}

// Lock ...
func (c *Client) Lock() {
	c.mutex.Lock()
}

// Unlock ...
func (c *Client) Unlock() {
	c.mutex.Unlock()
}

func getEnv(key string, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

func getClient(r *http.Request) *Client {
	sessionID := r.Header.Get("X-Session-Id")
	client := clients[sessionID]
	return client
}

// CORSRouterDecorator applies CORS headers to a mux.Router
type CORSRouterDecorator struct {
	R *mux.Router
}

func (c *CORSRouterDecorator) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if origin := req.Header.Get("Origin"); origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		rw.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		rw.Header().Set("Access-Control-Allow-Headers", "Accept, Accept-Language, Content-Type, X-Session-Id")
	}
	// Stop here if its Preflighted OPTIONS request
	if req.Method == "OPTIONS" {
		return
	}
	c.R.ServeHTTP(rw, req)
}

func handleRequests() {
	router := mux.NewRouter()

	router.HandleFunc("/wordlist", wordlist).Methods("GET")

	// Authenticate
	auth := router.PathPrefix("/auth").Subrouter()
	auth.HandleFunc("/login", login).Methods("POST")
	auth.HandleFunc("/register", register).Methods("GET")

	// Verified
	verified := router.PathPrefix("/").Subrouter()
	verified.Headers("X-Session-Id")
	verified.Use(verify)
	verified.HandleFunc("/auth/logout", logout).Methods("POST")

	// API
	api := verified.PathPrefix("/api").Subrouter()
	api.HandleFunc("/pwd", pwd).Methods("POST")
	api.HandleFunc("/upload", upload).Methods("POST")
	api.HandleFunc("/download", download).Methods("POST")
	api.HandleFunc("/info", info).Methods("POST")
	api.HandleFunc("/mkdir", mkdir).Methods("POST")
	api.HandleFunc("/cd", cd).Methods("POST")
	api.HandleFunc("/ls", ls).Methods("POST")
	api.HandleFunc("/refresh", refresh).Methods("POST")
	api.HandleFunc("/rm", rm).Methods("POST")
	api.HandleFunc("/publickey", publickey).Methods("POST")
	api.HandleFunc("/query", query).Methods("POST")

	// Start and Listen
	host := fmt.Sprintf("%s:%s", envHost, envPort)
	log.Printf(`Starting API on http://%s`, host)
	log.Fatal(http.ListenAndServe(host, &CORSRouterDecorator{router}))
}

// Start API Server
func Start() {
	envHost = getEnv("API_HOST", "0.0.0.0")
	envPort = getEnv("API_PORT", "8080")
	envData = getEnv("DATA_PATH", "/data")
	size, err := strconv.ParseInt(getEnv("SIZE", "1048576"), 10, 0)
	if err != nil || size <= 0 {
		log.Fatal("SIZE must be a number greater than 0")
	}
	envSize = int(size)

	clients = map[string]*Client{}
	handleRequests()
}
