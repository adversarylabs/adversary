package findingverify

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func WriteReport(name string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > 64<<20 {
		return fmt.Errorf("verification report exceeds 64 MiB")
	}
	// Atomically replace an explicitly requested artifact. Never leave a partial
	// replay file or follow a destination symlink. Reports contain private source.
	dir := filepath.Dir(name)
	file, err := os.CreateTemp(dir, ".verification-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, err = file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(temp, name)
}

func ReadReport(name string) (Report, error) {
	file, err := os.Open(name)
	if err != nil {
		return Report{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<20)+1))
	if err != nil {
		return Report{}, err
	}
	if len(data) > 64<<20 {
		return Report{}, fmt.Errorf("verification report exceeds 64 MiB")
	}
	var report Report
	if err = json.Unmarshal(data, &report); err != nil {
		return Report{}, err
	}
	if report.Version != Version {
		return Report{}, fmt.Errorf("unsupported verification report version")
	}
	return report, ValidateSnapshot(report.Snapshot)
}
