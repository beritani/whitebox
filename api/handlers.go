package api

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/beritani/whitebox/client"
)

// LocalHandlers stores files on local drive
type LocalHandlers struct {
	client.Handlers
	path string
}

// Upload ...
func (h LocalHandlers) Upload(id string, data []byte) error {
	return ioutil.WriteFile(fmt.Sprintf("%s/%s", h.path, id), data, 0777)
}

// Download ...
func (h LocalHandlers) Download(id string) ([]byte, error) {
	return ioutil.ReadFile(fmt.Sprintf("%s/%s", h.path, id))
}

// Delete ...
func (h LocalHandlers) Delete(id string) error {
	return os.Remove(fmt.Sprintf("%s/%s", h.path, id))
}

// Exists ...
func (h LocalHandlers) Exists(id string) bool {
	if _, err := os.Stat(fmt.Sprintf("%s/%s", h.path, id)); err != nil {
		return false
	}
	return true
}

// GetLocalHandlers ...
func GetLocalHandlers(path string) LocalHandlers {
	return LocalHandlers{
		path: filepath.Clean(path),
	}
}
