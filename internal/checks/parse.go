package checks

import (
	"strings"
)

// parseKeyValue parses "key = value" or "key value" config lines (pwquality,
// login.defs, journald), ignoring comments and [section] headers. Later
// assignments override earlier ones. Keys are lowercased.
func parseKeyValue(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		var k, v string
		if key, val, ok := strings.Cut(line, "="); ok {
			k, v = key, val
		} else {
			fields := strings.Fields(line)
			k = fields[0]
			v = strings.Join(fields[1:], " ")
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// mergeConfigs parses files in order, later files overriding earlier ones.
// Missing files are ignored; other read errors are returned.
func mergeConfigs(read func(string) ([]byte, error), paths []string) (map[string]string, []string, error) {
	merged := map[string]string{}
	var found []string
	for _, p := range paths {
		data, err := read(p)
		if err != nil {
			if isNotExist(err) {
				continue
			}
			return nil, nil, err
		}
		found = append(found, p)
		for k, v := range parseKeyValue(data) {
			merged[k] = v
		}
	}
	return merged, found, nil
}

// truncate shortens s for display.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func joinLimited(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + ", …"
}
