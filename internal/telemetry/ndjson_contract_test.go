package telemetry

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The NDJSON records are SessionEvent and anomalyRecord. Every JSON field of
// either is in the contract (schema/rtr-monitor-ndjson.v1.json), with the
// JSON type its Go type encodes to, and every field the contract lists is
// one of theirs. This catches a field added in code, even one no test
// emits (omitempty); the drift test in internal/cli checks the records
// actually written.
func TestNDJSONStructsMatchContract(t *testing.T) {
	data, err := os.ReadFile("../../schema/rtr-monitor-ndjson.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Type  any `json:"type"`
				Const any `json:"const"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}

	// The JSON type of each contract field, from every record type that
	// lists it; a field must have one type across record types.
	contract := map[string]string{}
	for def, d := range schema.Defs {
		for name, p := range d.Properties {
			typ, _ := p.Type.(string)
			if typ == "" && name == "event_type" {
				typ = "string" // a const per record type
			}
			if prev, ok := contract[name]; ok && prev != typ {
				t.Errorf("field %s is %s in one record type and %s in %s", name, prev, typ, def)
			}
			contract[name] = typ
		}
	}

	code := map[string]string{}
	for _, rt := range []reflect.Type{reflect.TypeOf(SessionEvent{}), reflect.TypeOf(anomalyRecord{})} {
		for i := range rt.NumField() {
			f := rt.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				t.Errorf("%s.%s has no JSON name", rt.Name(), f.Name)
				continue
			}
			typ := jsonTypeOfGo(f.Type)
			if prev, ok := code[name]; ok && prev != typ {
				t.Errorf("field %s encodes as %s in one record and %s in %s", name, prev, typ, rt.Name())
			}
			code[name] = typ
		}
	}

	var names []string
	for n := range code {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ct, ok := contract[n]
		switch {
		case !ok:
			t.Errorf("field %q is written by the code but not in the contract: add it to schema/rtr-monitor-ndjson.v1.json and docs/reference/telemetry-ndjson.md", n)
		case ct != code[n]:
			t.Errorf("field %q is %s in the contract but the code writes %s", n, ct, code[n])
		}
	}
	for n := range contract {
		if _, ok := code[n]; !ok {
			t.Errorf("field %q is in the contract but no record field writes it", n)
		}
	}
}

// jsonTypeOfGo is the JSON type encoding/json writes for a Go type.
func jsonTypeOfGo(t reflect.Type) string {
	if t == reflect.TypeOf(time.Time{}) {
		return "string"
	}
	if t == reflect.TypeOf(time.Duration(0)) {
		return "integer"
	}
	switch t.Kind() {
	case reflect.Pointer:
		return jsonTypeOfGo(t.Elem())
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Map, reflect.Struct:
		return "object"
	case reflect.Slice, reflect.Array:
		return "array"
	}
	return t.String()
}
