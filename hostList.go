package main

import (
	"bufio"
	"os"
	"strings"
)

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); len(line) > 0 && line[0] != '#' {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func dedup(in []string) (out []string) {
	m := make(map[string]struct{})
	for _, v := range in {
		if _, ok := m[v]; !ok {
			out = append(out, v)
			m[v] = struct{}{}
		}
	}
	return
}

func shorten(in []string) (out []string) {
	if len(in) < 2 {
		return in
	}
	prefix := strings.Split(in[0], ".")
	suffix := strings.Split(in[0], ".")

	for i := 1; i < len(in); i++ {
		parts := strings.Split(in[i], ".")
		for j := 0; j < len(prefix) && j < len(parts); j++ {
			if parts[j] != prefix[j] {
				prefix = prefix[:j]
				break
			}
		}
		for j, k := len(suffix)-1, len(parts)-1; j >= 0 && k >= 0; j, k = j-1, k-1 {
			if parts[k] != suffix[j] {
				suffix = suffix[j+1:]
				break
			}
		}
	}
	if len(prefix) == 0 && len(suffix) == 0 {
		return in
	}
	for _, v := range in {
		parts := strings.Split(v, ".")
		out = append(out, strings.Join(parts[len(prefix):len(parts)-len(suffix)], "."))
	}
	return
}
