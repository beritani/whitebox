package api

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/beritani/whitebox/core"
)

func upload(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	r.ParseMultipartForm(32 << 20)
	reader, _, err := r.FormFile("file")
	defer reader.Close()

	folder, err := client.GetFolderFromPath(client.Root(), r.FormValue("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	meta := core.Meta{
		Name: r.FormValue("name"),
		Tags: strings.Split(r.FormValue("tags"), ","),
	}

	data, err := ioutil.ReadAll(reader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	client.Upload(folder, meta, data)
}

func info(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	folder, err := client.GetFolderFromPath(client.Root(), r.FormValue("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	meta, err := json.Marshal(folder.Meta)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(meta)
}

func download(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	folder, err := client.GetFolderFromPath(client.Root(), r.FormValue("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	data, err := client.Download(folder.Parent, folder.Index)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Write(data)
}

func mkdir(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	path := filepath.Clean(r.FormValue("path"))

	folder, err := client.GetFolderFromPath(client.Root(), path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	meta := core.Meta{
		Name: r.FormValue("name"),
		Tags: strings.Split(r.FormValue("tags"), ","),
	}

	client.Mkdir(folder, meta)
}

func pwd(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	w.Write([]byte(client.PwdString()))
}

func cd(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	_, err := client.Cd(r.FormValue("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte(client.PwdString()))
}

func ls(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	folder, err := client.GetFolderFromPath(client.Root(), r.FormValue("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if folder == nil {
		http.Error(w, "Folder does not exist", http.StatusNotFound)
		return
	}

	files := client.Ls(folder)

	children := map[uint32]core.Meta{}
	for index, file := range files {
		children[index] = *file.Meta
	}

	data, err := json.Marshal(children)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func rm(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	folder, err := client.GetFolderFromPath(client.Root(), r.FormValue("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = client.Rm(folder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte("done"))
}

func refresh(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	folder, err := client.GetFolderFromPath(client.Root(), r.FormValue("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	client.Refresh(folder)
}

func publickey(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	path := filepath.Clean(r.FormValue("path"))

	folder, err := client.GetFolderFromPath(client.Root(), path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pubkey := client.GetExtendedPublicKey(folder)

	w.Write([]byte(pubkey))
}

func query(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	client.Lock()
	defer client.Unlock()

	path := filepath.Clean(r.FormValue("path"))
	query := r.FormValue("query")

	folder, err := client.GetFolderFromPath(client.Root(), path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	results, err := client.Find(folder, query, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	folders := make(map[string]interface{}, len(results))
	for _, f := range results {
		folders[f.Path] = f.Meta
	}

	data, err := json.Marshal(folders)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
