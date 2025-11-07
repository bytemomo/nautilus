package injector

import (
	"encoding/json"
	"net"
	"os"
)

// InjectionRequest defines a single packet injection request.
type InjectionRequest struct {
	TargetIP net.IP `json:"target_ip"`
	Payload  []byte `json:"payload"`
}

// Injector defines the interface for an injection module.
type Injector interface {
	GetInjectionRequests() ([]InjectionRequest, error)
}

// FileInjector is an implementation of Injector that reads requests from a file.
type FileInjector struct {
	FilePath string
}

// NewFileInjector creates a new FileInjector.
func NewFileInjector(filePath string) *FileInjector {
	return &FileInjector{FilePath: filePath}
}

// GetInjectionRequests reads and parses injection requests from the configured file.
func (i *FileInjector) GetInjectionRequests() ([]InjectionRequest, error) {
	data, err := os.ReadFile(i.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No file, no requests
		}
		return nil, err
	}

	if len(data) == 0 {
		return nil, nil // Empty file, no requests
	}

	var requests []InjectionRequest
	if err := json.Unmarshal(data, &requests); err != nil {
		return nil, err
	}

	// Clear the file to avoid re-injecting the same requests
	if err := os.Truncate(i.FilePath, 0); err != nil {
		return nil, err
	}

	return requests, nil
}
