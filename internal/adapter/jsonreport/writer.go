package jsonreport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	"bytemomo/orca/internal/domain"
)

type Writer struct {
	OutDir string // e.g., ./output
}

func New(out string) *Writer { return &Writer{OutDir: out} }

func (w *Writer) Save(target domain.HostPort, res domain.RunResult) error {
	dir := filepath.Join(w.OutDir, "runs")
	_ = os.MkdirAll(dir, 0o755)
	name := target.Host + "_" + strconv.Itoa(int(target.Port)) + ".json"
	return writeJSON(filepath.Join(dir, name), res)
}

func (w *Writer) Aggregate(all []domain.RunResult) (string, error) {
	_ = os.MkdirAll(w.OutDir, 0o755)
	path := filepath.Join(w.OutDir, "assessment.json")
	return path, writeJSON(path, struct {
		Version string             `json:"version"`
		Results []domain.RunResult `json:"results"`
	}{
		Version: "1.0",
		Results: all,
	})
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
