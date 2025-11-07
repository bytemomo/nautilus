package injector

import (
	"encoding/json"
	"net"
	"os"

	"github.com/sirupsen/logrus"
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
	logger   *logrus.Logger
}

// NewFileInjector creates a new FileInjector.
func NewFileInjector(filePath string, logger *logrus.Logger) *FileInjector {
	return &FileInjector{FilePath: filePath, logger: logger}
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
		i.logger.Errorf("Failed to unmarshal injection requests: %v", err)
		return nil, err
	}

	i.logger.Infof("Read %d injection requests from %s", len(requests), i.FilePath)

	// Clear the file to avoid re-injecting the same requests
	if err := os.Truncate(i.FilePath, 0); err != nil {
		i.logger.Errorf("Failed to truncate injection file: %v", err)
		return nil, err
	}

	return requests, nil
}
