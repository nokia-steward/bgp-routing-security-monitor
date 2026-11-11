package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// A checker for the subset of JSON Schema (draft 2020-12) that
// schema/rtr-monitor-ndjson.v1.json uses, with the standard library only.
// It knows these keywords:
//
//	$schema $id $comment title description format   annotations, ignored
//	$defs $ref (local, "#/$defs/name")
//	oneOf allOf if then
//	type const enum
//	required properties additionalProperties propertyNames
//	pattern minimum maximum
//
// and rejects a schema that uses any other keyword, so the schema can never
// rely on something the checker silently skips.

type jsonSchema struct {
	root map[string]any
}

var knownKeywords = map[string]bool{
	"$schema": true, "$id": true, "$comment": true, "title": true, "description": true, "format": true,
	"$defs": true, "$ref": true, "oneOf": true, "allOf": true, "if": true, "then": true,
	"type": true, "const": true, "enum": true,
	"required": true, "properties": true, "additionalProperties": true, "propertyNames": true,
	"pattern": true, "minimum": true, "maximum": true,
}

// loadSchema reads and checks a schema file.
func loadSchema(t *testing.T, path string) *jsonSchema {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		t.Fatalf("schema %s: %v", path, err)
	}
	if root["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema %s: $schema %v, want draft 2020-12", path, root["$schema"])
	}
	s := &jsonSchema{root: root}
	if errs := s.checkKeywords(root, "#"); len(errs) > 0 {
		t.Fatalf("schema %s uses keywords the checker does not implement:\n%s", path, strings.Join(errs, "\n"))
	}
	return s
}

// checkKeywords walks every subschema and reports unknown keywords.
func (s *jsonSchema) checkKeywords(node map[string]any, at string) []string {
	var errs []string
	for k, v := range node {
		if !knownKeywords[k] {
			errs = append(errs, fmt.Sprintf("%s: %s", at, k))
			continue
		}
		switch k {
		case "$defs", "properties":
			for name, sub := range v.(map[string]any) {
				errs = append(errs, s.checkKeywords(sub.(map[string]any), at+"/"+k+"/"+name)...)
			}
		case "oneOf", "allOf":
			for i, sub := range v.([]any) {
				errs = append(errs, s.checkKeywords(sub.(map[string]any), fmt.Sprintf("%s/%s/%d", at, k, i))...)
			}
		case "if", "then", "propertyNames":
			errs = append(errs, s.checkKeywords(v.(map[string]any), at+"/"+k)...)
		case "additionalProperties":
			if sub, ok := v.(map[string]any); ok {
				errs = append(errs, s.checkKeywords(sub, at+"/"+k)...)
			}
		}
	}
	return errs
}

// def returns the named $defs entry.
func (s *jsonSchema) def(name string) map[string]any {
	defs, _ := s.root["$defs"].(map[string]any)
	d, _ := defs[name].(map[string]any)
	return d
}

// validate checks a decoded JSON value (decoded with UseNumber) against
// schema and returns every violation, each prefixed with its location.
func (s *jsonSchema) validate(v any, schema map[string]any, at string) []string {
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, at+": "+fmt.Sprintf(format, args...)) }

	if ref, ok := schema["$ref"].(string); ok {
		name, ok := strings.CutPrefix(ref, "#/$defs/")
		target := s.def(name)
		if !ok || target == nil {
			fail("unresolvable $ref %q", ref)
		} else {
			errs = append(errs, s.validate(v, target, at)...)
		}
	}
	if subs, ok := schema["oneOf"].([]any); ok {
		pass := 0
		var closest []string // the errors of the branch for this record type
		for _, sub := range subs {
			e := s.validate(v, sub.(map[string]any), at)
			if len(e) == 0 {
				pass++
				continue
			}
			// A branch whose only quarrel is not the record type is the
			// one the record is meant to be: its errors say what drifted.
			if !slices.ContainsFunc(e, func(m string) bool { return strings.Contains(m, ".event_type: value") }) {
				closest = e
			}
		}
		switch {
		case pass == 0 && closest != nil:
			errs = append(errs, closest...)
		case pass == 0:
			fail("no record type matches (event_type %v)", eventTypeOf(v))
		case pass > 1:
			fail("matches %d of oneOf's %d schemas, want exactly 1", pass, len(subs))
		}
	}
	if subs, ok := schema["allOf"].([]any); ok {
		for _, sub := range subs {
			errs = append(errs, s.validate(v, sub.(map[string]any), at)...)
		}
	}
	if cond, ok := schema["if"].(map[string]any); ok && len(s.validate(v, cond, at)) == 0 {
		if then, ok := schema["then"].(map[string]any); ok {
			errs = append(errs, s.validate(v, then, at)...)
		}
	}
	if typ, ok := schema["type"]; ok {
		var types []string
		switch t := typ.(type) {
		case string:
			types = []string{t}
		case []any:
			for _, x := range t {
				types = append(types, x.(string))
			}
		}
		if !slices.ContainsFunc(types, func(t string) bool { return hasJSONType(v, t) }) {
			fail("type %s, want %s", jsonTypeOf(v), strings.Join(types, " or "))
		}
	}
	if c, ok := schema["const"]; ok && !jsonEqual(v, c) {
		fail("value %v, want %v", v, c)
	}
	if e, ok := schema["enum"].([]any); ok && !slices.ContainsFunc(e, func(x any) bool { return jsonEqual(v, x) }) {
		fail("value %v not in enum %v", v, e)
	}
	if str, ok := v.(string); ok {
		if p, ok := schema["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(str) {
			fail("%q does not match pattern %s", str, p)
		}
	}
	if n, ok := v.(json.Number); ok {
		f, _ := n.Float64()
		if m, ok := schema["minimum"].(json.Number); ok {
			if min, _ := m.Float64(); f < min {
				fail("%v below minimum %v", n, m)
			}
		}
		if m, ok := schema["maximum"].(json.Number); ok {
			if max, _ := m.Float64(); f > max {
				fail("%v above maximum %v", n, m)
			}
		}
	}
	if obj, ok := v.(map[string]any); ok {
		for _, r := range asStrings(schema["required"]) {
			if _, ok := obj[r]; !ok {
				fail("required field %q missing", r)
			}
		}
		props, _ := schema["properties"].(map[string]any)
		names := make([]string, 0, len(obj))
		for k := range obj {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if pn, ok := schema["propertyNames"].(map[string]any); ok {
				errs = append(errs, s.validate(k, pn, at+" (field name)")...)
			}
			if sub, ok := props[k].(map[string]any); ok {
				errs = append(errs, s.validate(obj[k], sub, at+"."+k)...)
				continue
			}
			switch ap := schema["additionalProperties"].(type) {
			case bool:
				if !ap {
					fail("field %q is not in the schema", k)
				}
			case map[string]any:
				errs = append(errs, s.validate(obj[k], ap, at+"."+k)...)
			}
		}
	}
	return errs
}

func asStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			out = append(out, x.(string))
		}
	}
	return out
}

func jsonTypeOf(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if hasJSONType(x, "integer") {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

func hasJSONType(v any, typ string) bool {
	switch typ {
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		_, err := n.Int64()
		return err == nil && !strings.ContainsAny(n.String(), ".eE")
	case "number":
		_, ok := v.(json.Number)
		return ok
	default:
		return jsonTypeOf(v) == typ
	}
}

func jsonEqual(a, b any) bool {
	an, aok := a.(json.Number)
	bn, bok := b.(json.Number)
	if aok && bok {
		af, _ := an.Float64()
		bf, _ := bn.Float64()
		return af == bf
	}
	return fmt.Sprint(a) == fmt.Sprint(b) && jsonTypeOf(a) == jsonTypeOf(b)
}

// The checker itself: it must reject what the drift test relies on it to
// reject, or a passing drift test would mean nothing.
func TestJSONSchemaSubsetChecker(t *testing.T) {
	s := loadSchema(t, ndjsonSchemaPath)
	decode := func(line string) any {
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	good := `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"connected","schema_version":1,"proto_version":2}`
	if errs := s.validate(decode(good), s.root, "line"); len(errs) != 0 {
		t.Fatalf("valid connected record rejected: %v", errs)
	}
	for name, line := range map[string]string{
		"unknown field":     `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"connected","schema_version":1,"proto_version":2,"extra":1}`,
		"missing required":  `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"connected","schema_version":1}`,
		"wrong type":        `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"connected","schema_version":1,"proto_version":"2"}`,
		"not an integer":    `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"connected","schema_version":1,"proto_version":1.5}`,
		"enum":              `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"connected","schema_version":1,"proto_version":3}`,
		"unknown type":      `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"hello","schema_version":1}`,
		"wrong version":     `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"connected","schema_version":2,"proto_version":2}`,
		"conditional field": `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"disconnected","schema_version":1,"proto_version":2,"disconnect_reason":"error_report"}`,
		"pattern":           `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"anomaly","schema_version":1,"category":"statistical","trigger":"vrp_total","severity":"high","z_scores":{},"raw":{}}`,
		"map key":           `{"timestamp":"2026-11-11T10:00:00Z","cache":"c:323","event_type":"anomaly","schema_version":1,"category":"statistical","trigger":"vrp_announced","severity":"high","z_scores":{"vrp_total":9},"raw":{}}`,
	} {
		if errs := s.validate(decode(line), s.root, "line"); len(errs) == 0 {
			t.Errorf("%s: invalid record accepted: %s", name, line)
		}
	}
}

func eventTypeOf(v any) any {
	if obj, ok := v.(map[string]any); ok {
		return obj["event_type"]
	}
	return nil
}
