package platform

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// MaxFileSize caps how much of any single file the scanner will read.
// Config files are tiny; anything bigger is either hostile or not a config file.
const MaxFileSize = 1 << 20 // 1 MiB

var (
	ErrNotRegular   = errors.New("not a regular file")
	ErrFileTooLarge = fmt.Errorf("file exceeds %d byte read limit", MaxFileSize)
)

// readFileSafe reads a regular file without ever blocking or exhausting memory.
//
//   - O_NONBLOCK stops open(2) from hanging on a FIFO planted at a config path.
//   - The type check is done with fstat on the opened descriptor, so the file
//     cannot be swapped between the check and the read (no TOCTOU).
//   - Reads are capped at MaxFileSize.
func readFileSafe(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}

	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%s: %w", path, ErrFileTooLarge)
	}
	return data, nil
}

// ReadFile reads a file relative to the host root.
func (h *Host) ReadFile(path string) ([]byte, error) {
	return readFileSafe(h.Path(path))
}

// Lstat returns file info for path without following a final symlink.
func (h *Host) Lstat(path string) (fs.FileInfo, error) {
	return os.Lstat(h.Path(path))
}

// Stat returns file info for path, following symlinks.
func (h *Host) Stat(path string) (fs.FileInfo, error) {
	return os.Stat(h.Path(path))
}

// Exists reports whether path exists on the host.
func (h *Host) Exists(path string) bool {
	_, err := os.Lstat(h.Path(path))
	return err == nil
}

// Glob matches pattern relative to the host root and returns host paths
// (with the root prefix stripped), sorted lexically.
func (h *Host) Glob(pattern string) ([]string, error) {
	matches, err := filepath.Glob(h.Path(pattern))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		rel, err := filepath.Rel(h.Root, m)
		if err != nil {
			continue
		}
		out = append(out, "/"+rel)
	}
	sort.Strings(out)
	return out, nil
}
