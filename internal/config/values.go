package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Keys returns the available settings in schema order.
func Keys() []string {
	return settingKeys(reflect.TypeFor[Settings]())
}

// Get returns a setting by its JSON field name.
func (s Settings) Get(key string) (any, error) {
	field, err := settingField(reflect.ValueOf(s), key)
	if err != nil {
		return nil, err
	}
	if field.Kind() == reflect.String {
		return field.String(), nil
	}
	return field.Interface(), nil
}

// Set updates a setting by its JSON field name, validating before changing s.
// Strings are accepted as plain text; other field types accept JSON values.
func (s *Settings) Set(key, input string) error {
	candidate := *s
	if err := setSettingValue(&candidate, key, input); err != nil {
		return err
	}
	if err := candidate.Normalize(); err != nil {
		return err
	}
	*s = candidate
	return nil
}

func settingName(field reflect.StructField) string {
	if !field.IsExported() {
		return ""
	}
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if name == "-" {
		return ""
	}
	if name == "" {
		return field.Name
	}
	return name
}

func settingKeys(schema reflect.Type) []string {
	var keys []string
	for i := 0; i < schema.NumField(); i++ {
		if name := settingName(schema.Field(i)); name != "" {
			keys = append(keys, name)
		}
	}
	return keys
}

func settingField(value reflect.Value, key string) (reflect.Value, error) {
	schema := value.Type()
	for i := 0; i < schema.NumField(); i++ {
		if name := settingName(schema.Field(i)); name != "" && name == key {
			return value.Field(i), nil
		}
	}
	return reflect.Value{}, fmt.Errorf("unknown setting %q; available settings: %s", key, strings.Join(settingKeys(schema), ", "))
}

func setSettingValue(target any, key, input string) error {
	field, err := settingField(reflect.ValueOf(target).Elem(), key)
	if err != nil {
		return err
	}
	if field.Kind() == reflect.String {
		if input == "" {
			return fmt.Errorf("value for %s must not be empty; use config unset %s to restore its default", key, key)
		}
		field.SetString(input)
		return nil
	}
	return decodeSettingJSON(field, key, []byte(input))
}

func decodeSettingJSON(field reflect.Value, key string, data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		switch field.Kind() {
		case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface:
		default:
			return fmt.Errorf("%s must not be null", key)
		}
	}
	parsed := reflect.New(field.Type())
	if err := json.Unmarshal(data, parsed.Interface()); err != nil {
		return fmt.Errorf("invalid value for %s: %w", key, err)
	}
	field.Set(parsed.Elem())
	return nil
}
