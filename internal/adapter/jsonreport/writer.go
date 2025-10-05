package jsonreport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"bytemomo/orca/internal/domain"
)

type Writer struct {
	OutDir string
}

func New(out string) *Writer { return &Writer{OutDir: out} }

func (w *Writer) Save(target domain.HostPort, res domain.RunResult) error {
	dir := filepath.Join(w.OutDir, "runs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := safeName(target.Host) + "_" + strconv.Itoa(int(target.Port)) + ".json"
	path := filepath.Join(dir, name)
	if err := writeJSONAtomic(path, res); err != nil {
		return err
	}
	return nil
}

func (w *Writer) Aggregate(all []domain.RunResult) (string, error) {
	if err := os.MkdirAll(w.OutDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(w.OutDir, "assessment.json")
	payload := struct {
		Version   string             `json:"version"`
		Generated string             `json:"generated_utc"`
		Results   []domain.RunResult `json:"results"`
	}{
		Version:   "1.0",
		Generated: time.Now().UTC().Format(time.RFC3339),
		Results:   all,
	}
	return path, writeJSONAtomic(path, payload)
}

// -------------------- helpers --------------------

var invalidRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeName(s string) string { return invalidRe.ReplaceAllString(s, "_") }

func writeJSONAtomic(path string, v any) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(sanitize(v)); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("encode json: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp: %w", err)
	}

	_ = os.Remove(path) // Windows-safe overwrite
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename into place: %w", err)
	}

	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func sanitize(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = sanitize(vv)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[fmt.Sprint(k)] = sanitize(vv)
		}
		return out
	case []any:
		for i := range t {
			t[i] = sanitize(t[i])
		}
		return t
	default:
		return t
	}
}
