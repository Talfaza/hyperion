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
	// #nosec G304 -- reading host config files by path is the scanner's job;
	// paths are constants or come from root-owned config (Include lines),
	// Host.Path keeps them under the scan root, and the read is read-only,
	// size-capped and limited to regular files.
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

var ErrUntrustedFile = errors.New("file is not safe to trust")

// ReadTrustedFile reads a configuration file whose contents change the
// scan's verdicts (the exceptions file), so it must not be writable by
// anyone less privileged than the scanner. The path is used as is, not
// under Host.Root.
//
//   - The file is opened with O_NOFOLLOW (no symlink at the final component)
//     and every check runs on the opened descriptor (no TOCTOU).
//   - It must be a regular file owned by root or by uid, not writable by group
//     or others, and at most MaxFileSize bytes.
//   - Its directory must satisfy the same ownership and write rules, so the
//     file cannot be replaced by renaming another one over it.
func ReadTrustedFile(path string, uid int) ([]byte, error) {
	trusted := func(info fs.FileInfo, what string) error {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s %s: cannot read ownership: %w", what, path, ErrUntrustedFile)
		}
		if st.Uid != 0 && int(st.Uid) != uid {
			return fmt.Errorf("%s %s is owned by uid %d (want root or uid %d): %w", what, path, st.Uid, uid, ErrUntrustedFile)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s %s has mode %04o, writable by group or others: %w", what, path, info.Mode().Perm(), ErrUntrustedFile)
		}
		return nil
	}

	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := trusted(dir, "directory of"); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is the operator-supplied exceptions file; ownership and mode are verified below
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symlink: %w", path, ErrUntrustedFile)
		}
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
	if err := trusted(info, "file"); err != nil {
		return nil, err
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

// Readlink returns the target of a symlink (e.g. /dev/mapper/x -> ../dm-0).
func (h *Host) Readlink(path string) (string, error) {
	return os.Readlink(h.Path(path))
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
