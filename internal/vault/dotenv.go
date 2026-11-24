package vault

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ParseDotenv parses .env formatted content into a map of key-value pairs.
// It supports comments (#), blank lines, optional `export ` prefix,
// single-quoted literals, double-quoted strings with escapes, and unquoted values
// with inline comments.
func ParseDotenv(r io.Reader) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		} else if strings.HasPrefix(line, "export\t") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export\t"))
		}

		eqIdx := strings.IndexByte(line, '=')
		if eqIdx <= 0 {
			return nil, fmt.Errorf("line %d: invalid syntax (expected KEY=VALUE)", lineNum)
		}

		key := strings.TrimSpace(line[:eqIdx])
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", lineNum)
		}

		rawVal := strings.TrimSpace(line[eqIdx+1:])
		val, err := parseDotenvValue(rawVal)
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", lineNum, key, err)
		}
		result[key] = val
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading .env: %w", err)
	}
	return result, nil
}

func parseDotenvValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}

	switch raw[0] {
	case '\'':
		// Single-quoted: literal until closing single quote.
		endIdx := strings.IndexByte(raw[1:], '\'')
		if endIdx == -1 {
			return "", fmt.Errorf("unterminated single-quoted value")
		}
		rest := strings.TrimSpace(raw[1+endIdx+1:])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return "", fmt.Errorf("unexpected trailing characters after closing quote")
		}
		return raw[1 : 1+endIdx], nil

	case '"':
		// Double-quoted: handle escape sequences.
		var sb strings.Builder
		escaped := false
		closed := false
		var rest string

		for i := 1; i < len(raw); i++ {
			ch := raw[i]
			if escaped {
				switch ch {
				case 'n':
					sb.WriteByte('\n')
				case 'r':
					sb.WriteByte('\r')
				case 't':
					sb.WriteByte('\t')
				case '"', '\\', '$':
					sb.WriteByte(ch)
				default:
					sb.WriteByte('\\')
					sb.WriteByte(ch)
				}
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				closed = true
				rest = strings.TrimSpace(raw[i+1:])
				break
			}
			sb.WriteByte(ch)
		}
		if !closed {
			return "", fmt.Errorf("unterminated double-quoted value")
		}
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return "", fmt.Errorf("unexpected trailing characters after closing quote")
		}
		return sb.String(), nil

	default:
		// Unquoted: strip inline comments preceded by whitespace or immediately if #
		if idx := strings.Index(raw, " #"); idx != -1 {
			raw = raw[:idx]
		} else if idx := strings.Index(raw, "\t#"); idx != -1 {
			raw = raw[:idx]
		}
		return strings.TrimSpace(raw), nil
	}
}

// FormatDotenv formats a secret map into deterministic, safely quoted .env lines.
func FormatDotenv(secrets map[string]string) string {
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		v := secrets[k]
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(quoteDotenvValue(v))
		sb.WriteByte('\n')
	}
	return sb.String()
}

func quoteDotenvValue(v string) string {
	if v == "" {
		return `""`
	}
	needsQuote := strings.ContainsAny(v, " \t\r\n#\"'\\$")
	if !needsQuote {
		return v
	}
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			sb.WriteString(`\\`)
		case '"':
			sb.WriteString(`\"`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			sb.WriteByte(v[i])
		}
	}
	sb.WriteByte('"')
	return sb.String()
}
