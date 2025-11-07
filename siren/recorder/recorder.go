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

func (s *RecorderStats) update(records, bytes, failed uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RecordsWritten += records
	s.BytesWritten += bytes
	s.RecordsFailed += failed
}

var formatWriters = map[string]func(r *Recorder) (uint64, uint64, error){
	"json": (*Recorder).writeJSON,
	"pcap": (*Recorder).writePCAP,
	"raw":  (*Recorder).writeRaw,
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

// flushUnlocked flushes the buffer to the configured output file.
// The caller must hold the mutex.
func (r *Recorder) flushUnlocked() error {
	if len(r.buffer) == 0 {
		return nil
	}

	if err := r.checkAndRotateFile(); err != nil {
		r.handleWriteError(err, len(r.buffer))
		return fmt.Errorf("failed to rotate file: %w", err)
	}

	writer, ok := formatWriters[strings.ToLower(r.config.Format)]
	if !ok {
		writer = (*Recorder).writePCAP // Default to PCAP
	}

	recordsWritten, bytesWritten, err := writer(r)
	if err != nil {
		r.handleWriteError(err, len(r.buffer))
		return err
	}

	r.stats.update(recordsWritten, bytesWritten, 0)
	r.buffer = r.buffer[:0] // Clear buffer
	return nil
}

func (r *Recorder) handleWriteError(err error, numRecords int) {
	fmt.Fprintf(os.Stderr, "recorder: write error: %v\n", err)
	r.stats.update(0, 0, uint64(numRecords))
}

func (r *Recorder) writeJSON() (uint64, uint64, error) {
	var bytesWritten uint64
	for _, record := range r.buffer {
		err := r.encoder.Encode(record)
		if err != nil {
			return 0, 0, err
		}
		// Note: We don't have an exact byte count from the encoder, so this is an estimate.
		bytesWritten += uint64(len(record.Payload) + 100) // Rough estimate
	}
	return uint64(len(r.buffer)), bytesWritten, nil
}

func (r *Recorder) writePCAP() (uint64, uint64, error) {
	var bytesWritten uint64
	var recordsWritten uint64
	buf := make([]byte, 16) // Buffer for PCAP record header

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

		binary.LittleEndian.PutUint32(buf[0:4], hdr.TsSec)
		binary.LittleEndian.PutUint32(buf[4:8], hdr.TsUsec)
		binary.LittleEndian.PutUint32(buf[8:12], hdr.InclLen)
		binary.LittleEndian.PutUint32(buf[12:16], hdr.OrigLen)

		if _, err := r.file.Write(buf); err != nil {
			return recordsWritten, bytesWritten, err
		}
		if _, err := r.file.Write(record.Data); err != nil {
			return recordsWritten, bytesWritten, err
		}

		bytesWritten += uint64(16 + len(record.Data))
		recordsWritten++
	}
	return recordsWritten, bytesWritten, nil
}

func (r *Recorder) writeRaw() (uint64, uint64, error) {
	var bytesWritten uint64
	buf := make([]byte, 12) // Buffer for timestamp and size

	for _, record := range r.buffer {
		binary.BigEndian.PutUint64(buf[0:8], uint64(record.Timestamp.Unix()))
		binary.BigEndian.PutUint32(buf[8:12], uint32(record.Size))

		if _, err := r.file.Write(buf); err != nil {
			return uint64(len(r.buffer)), bytesWritten, err
		}
		if record.Payload != nil {
			if _, err := r.file.Write(record.Payload); err != nil {
				return uint64(len(r.buffer)), bytesWritten, err
			}
		}
		bytesWritten += uint64(12 + len(record.Payload))
	}
	return uint64(len(r.buffer)), bytesWritten, nil
}

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

func (r *Recorder) checkAndRotateFile() error {
	if r.config.MaxFileSize <= 0 {
		return nil
	}
	if r.stats.CurrentFileSize < r.config.MaxFileSize {
		return nil
	}
	return r.rotateFile()
}

func (r *Recorder) rotateFile() error {
	r.file.Close()
	timestamp := time.Now().Format("20060102-150405")
	ext := ".pcap" // default extension
	base := strings.TrimSuffix(r.config.OutputPath, ext)
	newPath := fmt.Sprintf("%s-%s%s", base, timestamp, ext)

	if err := os.Rename(r.config.OutputPath, newPath); err != nil {
		return fmt.Errorf("failed to rename old log file: %w", err)
	}

	file, err := os.OpenFile(r.config.OutputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open new log file: %w", err)
	}
	r.file = file

	if r.config.Format == "json" {
		r.encoder = json.NewEncoder(file)
	} else if r.config.Format == "pcap" {
		r.pcapHeaderWritten = false
		if err := r.writePCAPHeader(); err != nil {
			// Attempt to clean up and restore state
			r.file.Close()
			os.Rename(newPath, r.config.OutputPath)
			return fmt.Errorf("failed to write pcap header to new file: %w", err)
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
