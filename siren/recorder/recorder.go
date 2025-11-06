package recorder

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultSnapLen = 256

// TrafficRecord represents a single traffic event
type TrafficRecord struct {
	Timestamp    time.Time              `json:"timestamp"`
	ConnectionID string                 `json:"connection_id,omitempty"`
	Direction    string                 `json:"direction"`
	Payload      []byte                 `json:"payload,omitempty"`
	Size         int                    `json:"size"`
	Dropped      bool                   `json:"dropped,omitempty"`
	Modified     bool                   `json:"modified,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Data         []byte                 `json:"-"`
	OriginalLen  int                    `json:"-"`
}

// RecorderConfig configures the recorder
type RecorderConfig struct {
	OutputPath     string
	Format         string // "json", "pcap", "raw"
	BufferSize     int
	FlushInterval  time.Duration
	IncludePayload bool
	MaxFileSize    int64 // Rotate when file reaches this size
	Compress       bool
}

// DefaultRecorderConfig returns default configuration
func DefaultRecorderConfig() *RecorderConfig {
	return &RecorderConfig{
		OutputPath:     "captures/traffic.pcap",
		Format:         "pcap",
		BufferSize:     1000,
		FlushInterval:  5 * time.Second,
		IncludePayload: true,
		MaxFileSize:    100 * 1024 * 1024, // 100MB
		Compress:       false,
	}
}

// Recorder records traffic for analysis
type Recorder struct {
	config            *RecorderConfig
	file              *os.File
	encoder           *json.Encoder
	buffer            []*TrafficRecord
	mu                sync.Mutex
	running           bool
	stopCh            chan struct{}
	wg                sync.WaitGroup
	stats             *RecorderStats
	pcapHeaderWritten bool
}

// RecorderStats tracks recorder statistics
type RecorderStats struct {
	mu              sync.RWMutex
	RecordsWritten  uint64
	BytesWritten    uint64
	RecordsFailed   uint64
	FileRotations   uint64
	CurrentFileSize int64
}

type pcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

type pcapRecordHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// NewRecorder creates a new traffic recorder
func NewRecorder(config *RecorderConfig) (*Recorder, error) {
	if config == nil {
		config = DefaultRecorderConfig()
	}

	// Create output directory if it doesn't exist
	dir := config.OutputPath[:len(config.OutputPath)-len(config.OutputPath[findLastSlash(config.OutputPath):])]
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Open output file
	file, err := os.OpenFile(config.OutputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open output file: %w", err)
	}

	r := &Recorder{
		config:  config,
		file:    file,
		buffer:  make([]*TrafficRecord, 0, config.BufferSize),
		stopCh:  make(chan struct{}),
		stats:   &RecorderStats{},
		running: false,
	}

	if config.Format == "json" {
		r.encoder = json.NewEncoder(file)
	}

	if strings.EqualFold(config.Format, "pcap") {
		if err := r.writePCAPHeader(); err != nil {
			return nil, err
		}
	}

	return r, nil
}

func (r *Recorder) writePCAPHeader() error {
	if r.pcapHeaderWritten {
		return nil
	}
	header := pcapGlobalHeader{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      uint32(defaultSnapLen),
		Network:      1, // LINKTYPE_ETHERNET
	}
	if err := binary.Write(r.file, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("failed to write pcap header: %w", err)
	}
	r.pcapHeaderWritten = true
	return nil
}

// Start begins recording
func (r *Recorder) Start() error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("recorder already running")
	}
	r.running = true
	r.mu.Unlock()

	// Start flush goroutine
	r.wg.Add(1)
	go r.flushLoop()

	return nil
}

// Stop stops recording and flushes remaining data
func (r *Recorder) Stop() error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	r.running = false
	r.mu.Unlock()

	// Signal stop
	close(r.stopCh)

	// Wait for flush goroutine
	r.wg.Wait()

	// Final flush
	if err := r.Flush(); err != nil {
		return err
	}

	// Close file
	if r.file != nil {
		return r.file.Close()
	}

	return nil
}

// Record adds a traffic record to the buffer
func (r *Recorder) Record(record *TrafficRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return
	}

	// Don't include payload if configured not to
	if !r.config.IncludePayload {
		record.Payload = nil
	}
	if len(record.Data) > 0 {
		if len(record.Data) > defaultSnapLen {
			record.Data = append([]byte(nil), record.Data[:defaultSnapLen]...)
		} else {
			record.Data = append([]byte(nil), record.Data...)
		}
	}

	r.buffer = append(r.buffer, record)

	// Flush if buffer is full
	if len(r.buffer) >= r.config.BufferSize {
		r.flushUnlocked()
	}
}

// Flush writes buffered records to disk
func (r *Recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushUnlocked()
}

// flushUnlocked flushes without acquiring the lock (caller must hold lock)
func (r *Recorder) flushUnlocked() error {
	if len(r.buffer) == 0 {
		return nil
	}

	// Check if we need to rotate the file
	if r.config.MaxFileSize > 0 {
		stat, err := r.file.Stat()
		if err == nil && stat.Size() >= r.config.MaxFileSize {
			if err := r.rotateFile(); err != nil {
				return err
			}
		}
	}

	// Write records based on format
	var err error
	switch strings.ToLower(r.config.Format) {
	case "json":
		err = r.writeJSON()
	case "raw":
		err = r.writeRaw()
	case "pcap":
		err = r.writePCAP()
	default:
		err = r.writePCAP()
	}

	if err != nil {
		r.stats.mu.Lock()
		r.stats.RecordsFailed += uint64(len(r.buffer))
		r.stats.mu.Unlock()
		return err
	}

	// Update stats
	r.stats.mu.Lock()
	r.stats.RecordsWritten += uint64(len(r.buffer))
	r.stats.mu.Unlock()

	// Clear buffer
	r.buffer = r.buffer[:0]

	return nil
}

// writeJSON writes records as JSON lines
func (r *Recorder) writeJSON() error {
	for _, record := range r.buffer {
		if err := r.encoder.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func (r *Recorder) writePCAP() error {
	if err := r.writePCAPHeader(); err != nil {
		return err
	}
	for _, record := range r.buffer {
		if len(record.Data) == 0 {
			continue
		}
		ts := record.Timestamp
		hdr := pcapRecordHeader{
			TsSec:   uint32(ts.Unix()),
			TsUsec:  uint32(ts.Nanosecond() / 1000),
			InclLen: uint32(len(record.Data)),
			OrigLen: uint32(record.OriginalLen),
		}
		if hdr.OrigLen == 0 {
			hdr.OrigLen = hdr.InclLen
		}
		if err := binary.Write(r.file, binary.LittleEndian, &hdr); err != nil {
			return err
		}
		if _, err := r.file.Write(record.Data); err != nil {
			return err
		}

		r.stats.BytesWritten += uint64(16 + len(record.Data))
		r.stats.CurrentFileSize += int64(16 + len(record.Data))
	}
	return nil
}

// writeRaw writes records as raw binary
func (r *Recorder) writeRaw() error {
	for _, record := range r.buffer {
		// Write timestamp (8 bytes)
		ts := record.Timestamp.Unix()
		if _, err := r.file.Write([]byte{
			byte(ts >> 56), byte(ts >> 48), byte(ts >> 40), byte(ts >> 32),
			byte(ts >> 24), byte(ts >> 16), byte(ts >> 8), byte(ts),
		}); err != nil {
			return err
		}

		// Write size (4 bytes)
		size := uint32(record.Size)
		if _, err := r.file.Write([]byte{
			byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size),
		}); err != nil {
			return err
		}

		// Write payload
		if record.Payload != nil {
			if _, err := r.file.Write(record.Payload); err != nil {
				return err
			}
		}

		r.stats.mu.Lock()
		r.stats.BytesWritten += uint64(12 + len(record.Payload))
		r.stats.CurrentFileSize += int64(12 + len(record.Payload))
		r.stats.mu.Unlock()
	}
	return nil
}

// flushLoop periodically flushes the buffer
func (r *Recorder) flushLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.Flush()
		case <-r.stopCh:
			return
		}
	}
}

// rotateFile closes current file and opens a new one
func (r *Recorder) rotateFile() error {
	// Close current file
	if err := r.file.Close(); err != nil {
		return err
	}

	// Rename current file with timestamp
	timestamp := time.Now().Format("20060102_150405")
	oldPath := r.config.OutputPath
	newPath := fmt.Sprintf("%s.%s", oldPath, timestamp)
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}

	// Open new file
	file, err := os.OpenFile(oldPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	r.file = file
	if r.config.Format == "json" {
		r.encoder = json.NewEncoder(file)
	}
	if strings.EqualFold(r.config.Format, "pcap") {
		r.pcapHeaderWritten = false
		if err := r.writePCAPHeader(); err != nil {
			return err
		}
	}

	r.stats.mu.Lock()
	r.stats.FileRotations++
	r.stats.CurrentFileSize = 0
	r.stats.mu.Unlock()

	return nil
}

// Stats returns recorder statistics
func (r *Recorder) Stats() *RecorderStats {
	r.stats.mu.RLock()
	defer r.stats.mu.RUnlock()

	return &RecorderStats{
		RecordsWritten:  r.stats.RecordsWritten,
		BytesWritten:    r.stats.BytesWritten,
		RecordsFailed:   r.stats.RecordsFailed,
		FileRotations:   r.stats.FileRotations,
		CurrentFileSize: r.stats.CurrentFileSize,
	}
}

// findLastSlash finds the last slash in a path
func findLastSlash(path string) int {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return i
		}
	}
	return -1
}

// ReadRecords reads records from a file
func ReadRecords(path string) ([]*TrafficRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []*TrafficRecord
	decoder := json.NewDecoder(file)

	for {
		var record TrafficRecord
		if err := decoder.Decode(&record); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		records = append(records, &record)
	}

	return records, nil
}
