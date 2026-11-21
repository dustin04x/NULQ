// Package lab validates NULQ laboratory runs: report schemas, scenario
// expectations, coverage and container isolation.
//
// It deliberately implements only the JSON Schema constructs the published
// NULQ schema uses. That keeps the laboratory dependency-free while still
// validating the real artifact rather than a hand-copied shape. An independent
// validator (Python jsonschema, when installed) is used by the lab script as a
// cross-check.
package lab

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Schema is a compiled JSON Schema document.
type Schema struct {
	root     map[string]any
	patterns map[string]*regexp.Regexp
}

// LoadSchema reads and parses a JSON Schema file.
func LoadSchema(path string) (*Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	return &Schema{root: root, patterns: make(map[string]*regexp.Regexp)}, nil
}

// ValidateFile validates the JSON document at path and returns human-readable
// violations. An empty slice means the document conforms.
func (s *Schema) ValidateFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("$: cannot read document: %v", err)}
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return []string{fmt.Sprintf("$: invalid JSON: %v", err)}
	}
	return s.Validate(document)
}

// Validate checks a decoded JSON document against the schema root.
func (s *Schema) Validate(document any) []string {
	var problems []string
	s.validate(document, s.root, "$", &problems, 0)
	return problems
}

func (s *Schema) validate(value any, schema map[string]any, path string, problems *[]string, depth int) {
	if depth > 32 {
		*problems = append(*problems, path+": schema nesting is too deep")
		return
	}
	if ref, ok := schema["$ref"].(string); ok {
		target, ok := s.resolve(ref)
		if !ok {
			*problems = append(*problems, path+": unresolved $ref "+ref)
			return
		}
		s.validate(value, target, path, problems, depth+1)
		return
	}

	if want, ok := schema["type"]; ok {
		for _, name := range stringList(want) {
			if !typeMatches(value, name) {
				*problems = append(*problems, fmt.Sprintf("%s: expected type %s", path, name))
				return
			}
		}
	}

	if constant, ok := schema["const"]; ok && !reflect.DeepEqual(constant, value) {
		*problems = append(*problems, fmt.Sprintf("%s: expected constant %v", path, constant))
	}

	if options, ok := schema["enum"].([]any); ok {
		found := false
		for _, option := range options {
			if reflect.DeepEqual(option, value) {
				found = true
				break
			}
		}
		if !found {
			*problems = append(*problems, fmt.Sprintf("%s: %v is not one of %v", path, value, options))
		}
	}

	switch typed := value.(type) {
	case map[string]any:
		s.validateObject(typed, schema, path, problems, depth)
	case []any:
		s.validateArray(typed, schema, path, problems, depth)
	case string:
		s.validateString(typed, schema, path, problems)
	case float64:
		if minimum, ok := number(schema["minimum"]); ok && typed < minimum {
			*problems = append(*problems, fmt.Sprintf("%s: %v is below minimum %v", path, typed, minimum))
		}
		if maximum, ok := number(schema["maximum"]); ok && typed > maximum {
			*problems = append(*problems, fmt.Sprintf("%s: %v is above maximum %v", path, typed, maximum))
		}
	}

	if format, ok := schema["format"].(string); ok {
		if text, ok := value.(string); ok {
			switch format {
			case "date-time":
				if _, err := time.Parse(time.RFC3339, text); err != nil {
					*problems = append(*problems, fmt.Sprintf("%s: %q is not an RFC 3339 date-time", path, text))
				}
			case "uri":
				parsed, err := url.Parse(text)
				if err != nil || parsed.Scheme == "" {
					*problems = append(*problems, fmt.Sprintf("%s: %q is not an absolute URI", path, text))
				}
			}
		}
	}
}

func (s *Schema) validateObject(value map[string]any, schema map[string]any, path string, problems *[]string, depth int) {
	properties, _ := schema["properties"].(map[string]any)

	if required, ok := schema["required"].([]any); ok {
		for _, name := range stringList(required) {
			if _, present := value[name]; !present {
				*problems = append(*problems, fmt.Sprintf("%s: missing required property %q", path, name))
			}
		}
	}

	for name, propertySchema := range properties {
		child, present := value[name]
		if !present {
			continue
		}
		childSchema, ok := propertySchema.(map[string]any)
		if !ok {
			continue
		}
		s.validate(child, childSchema, path+"."+name, problems, depth+1)
	}

	additional, hasRule := schema["additionalProperties"]
	if !hasRule {
		return
	}
	if allowed, ok := additional.(bool); ok && !allowed {
		for name := range value {
			if _, known := properties[name]; !known {
				*problems = append(*problems, fmt.Sprintf("%s: unexpected property %q", path, name))
			}
		}
		return
	}
	if additionalSchema, ok := additional.(map[string]any); ok {
		for name, child := range value {
			if _, known := properties[name]; known {
				continue
			}
			s.validate(child, additionalSchema, path+"."+name, problems, depth+1)
		}
	}
}

func (s *Schema) validateArray(value []any, schema map[string]any, path string, problems *[]string, depth int) {
	if minimum, ok := number(schema["minItems"]); ok && float64(len(value)) < minimum {
		*problems = append(*problems, fmt.Sprintf("%s: needs at least %v items", path, minimum))
	}
	items, ok := schema["items"].(map[string]any)
	if !ok {
		return
	}
	for i, child := range value {
		s.validate(child, items, fmt.Sprintf("%s[%d]", path, i), problems, depth+1)
	}
}

func (s *Schema) validateString(value string, schema map[string]any, path string, problems *[]string) {
	if minimum, ok := number(schema["minLength"]); ok && utf8.RuneCountInString(value) < int(minimum) {
		*problems = append(*problems, fmt.Sprintf("%s: string is shorter than %v characters", path, minimum))
	}
	pattern, ok := schema["pattern"].(string)
	if !ok {
		return
	}
	compiled, cached := s.patterns[pattern]
	if !cached {
		var err error
		compiled, err = regexp.Compile(pattern)
		if err != nil {
			*problems = append(*problems, fmt.Sprintf("%s: schema pattern %q does not compile: %v", path, pattern, err))
			return
		}
		s.patterns[pattern] = compiled
	}
	if !compiled.MatchString(value) {
		*problems = append(*problems, fmt.Sprintf("%s: %q does not match %s", path, value, pattern))
	}
}

// resolve handles local JSON Pointer references of the form "#/$defs/name".
func (s *Schema) resolve(ref string) (map[string]any, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	current := any(s.root)
	for _, token := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[token]
		if !ok {
			return nil, false
		}
	}
	resolved, ok := current.(map[string]any)
	return resolved, ok
}

func typeMatches(value any, name string) bool {
	switch name {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		_, ok := value.(float64)
		return ok
	case "integer":
		number, ok := value.(float64)
		return ok && math.Trunc(number) == number
	case "null":
		return value == nil
	default:
		return true
	}
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}

func number(value any) (float64, bool) {
	parsed, ok := value.(float64)
	return parsed, ok
}
