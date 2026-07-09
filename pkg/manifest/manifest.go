package manifest

import (
	"fmt"
	"os"
	"strings"
)

const FileName = "adversary.yaml"

type Manifest struct {
	Name        string
	Version     string
	Description string
	Runtime     Runtime
	Permissions Permissions
}

type Runtime struct {
	Name    string
	Version string
	Command []string
}

type Permissions struct {
	Network string
}

func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	return Parse(data)
}

func Parse(data []byte) (Manifest, error) {
	text := string(data)
	var out Manifest
	var section string
	var list string
	for _, raw := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := leadingSpaces(raw)
		if strings.HasPrefix(trimmed, "- ") {
			if list == "runtime.command" {
				out.Runtime.Command = append(out.Runtime.Command, scalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))))
			}
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return Manifest{}, fmt.Errorf("invalid manifest line: %s", raw)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if indent == 0 {
			section = key
			list = ""
			switch key {
			case "name":
				out.Name = scalar(value)
			case "version":
				out.Version = scalar(value)
			case "description":
				out.Description = scalar(value)
			}
			continue
		}
		switch section {
		case "runtime":
			if indent == 2 {
				switch key {
				case "name", "type":
					out.Runtime.Name = scalar(value)
				case "version":
					out.Runtime.Version = scalar(value)
				case "command":
					list = "runtime.command"
				}
			}
		case "permissions":
			if indent == 2 && key == "network" {
				out.Permissions.Network = scalar(value)
			}
		}
	}
	if out.Name == "" {
		return Manifest{}, fmt.Errorf("manifest name is required")
	}
	if out.Runtime.Name == "" {
		return Manifest{}, fmt.Errorf("manifest runtime.name is required")
	}
	if out.Runtime.Version == "" {
		return Manifest{}, fmt.Errorf("manifest runtime.version is required")
	}
	return out, nil
}

func ShortName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, "/")
	parts := strings.Split(name, "/")
	return parts[len(parts)-1]
}

func leadingSpaces(s string) int {
	count := 0
	for count < len(s) && s[count] == ' ' {
		count++
	}
	return count
}

func scalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
	}
	return s
}
