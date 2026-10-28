package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
)

const DefaultProfile = "default"

// Overrides stores only user-supplied settings, including keys from newer releases.
type Overrides map[string]json.RawMessage

// Document is the on-disk config structure. Each profile independently inherits
// DefaultSettings; profiles do not inherit settings from one another.
type Document struct {
	ActiveProfile string               `json:"active_profile"`
	Profiles      map[string]Overrides `json:"profiles"`
	extra         map[string]json.RawMessage
}

// DefaultDocument defines the initial profile selection without creating a file.
func DefaultDocument() *Document {
	return &Document{
		ActiveProfile: DefaultProfile,
		Profiles:      map[string]Overrides{DefaultProfile: {}},
	}
}

var profileNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func validateProfileName(name string) error {
	if !profileNamePattern.MatchString(name) {
		return errors.New("profile name must be 1-64 letters, digits, hyphens or underscores, starting with a letter or digit")
	}
	return nil
}

func (d *Document) profile(name string) (Overrides, error) {
	if name == "" {
		name = d.ActiveProfile
	}
	profile, ok := d.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q does not exist", name)
	}
	return profile, nil
}

// Saved returns an independent copy of the selected profile's explicit overrides.
// An empty name selects the active profile.
func (d *Document) Saved(name string) (Overrides, error) {
	profile, err := d.profile(name)
	if err != nil {
		return nil, err
	}
	copy := make(Overrides, len(profile))
	for key, value := range profile {
		copy[key] = append(json.RawMessage(nil), value...)
	}
	return copy, nil
}

// Effective overlays the profile's known settings on current built-in defaults.
// Unknown settings remain stored for compatibility but do not affect this version.
func (d *Document) Effective(name string) (Settings, error) {
	return d.effectiveSettings(name, Keys())
}

// EffectiveValue resolves and validates one setting independently. Discovery
// commands can read their IP type without requiring a valid country or city.
func (d *Document) EffectiveValue(name, key string) (any, error) {
	settings, err := d.effectiveSettings(name, []string{key})
	if err != nil {
		return nil, err
	}
	return settings.Get(key)
}

func (d *Document) effectiveSettings(name string, keys []string) (Settings, error) {
	if name == "" {
		name = d.ActiveProfile
	}
	profile, err := d.profile(name)
	if err != nil {
		return Settings{}, err
	}
	settings := DefaultSettings()
	for _, key := range keys {
		if value, ok := profile[key]; ok {
			field, err := settingField(reflect.ValueOf(&settings).Elem(), key)
			if err != nil {
				return Settings{}, err
			}
			if err := decodeSettingJSON(field, key, value); err != nil {
				return Settings{}, fmt.Errorf("profile %q: %w", name, err)
			}
		}
	}
	if err := settings.Normalize(); err != nil {
		return Settings{}, fmt.Errorf("profile %q: %w", name, err)
	}
	return settings, nil
}

// Set validates and writes one override, preserving all other properties.
func (d *Document) Set(name, key, input string) error {
	profile, err := d.profile(name)
	if err != nil {
		return err
	}
	// Validate the new value independently so existing bad values can be repaired
	// one at a time without discarding unrelated or unrecognized settings.
	settings := DefaultSettings()
	if err := settings.Set(key, input); err != nil {
		return err
	}
	value, err := settings.Get(key)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	profile[key] = encoded
	return nil
}

// Unset removes an override so this and future versions use their built-in value.
func (d *Document) Unset(name, key string) error {
	if _, err := DefaultSettings().Get(key); err != nil {
		return err
	}
	profile, err := d.profile(name)
	if err != nil {
		return err
	}
	delete(profile, key)
	return nil
}

// Names lists profiles in a stable order.
func (d *Document) Names() []string {
	names := make([]string, 0, len(d.Profiles))
	for name := range d.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Create adds an empty profile that inherits only built-in defaults.
func (d *Document) Create(name string) error {
	if err := validateProfileName(name); err != nil {
		return err
	}
	if _, exists := d.Profiles[name]; exists {
		return fmt.Errorf("profile %q already exists", name)
	}
	d.Profiles[name] = Overrides{}
	return nil
}

// Use changes the selected profile without changing the running tunnel.
func (d *Document) Use(name string) error {
	if err := validateProfileName(name); err != nil {
		return err
	}
	if _, err := d.Effective(name); err != nil {
		return err
	}
	d.ActiveProfile = name
	return nil
}

// Delete removes an inactive, non-default profile.
func (d *Document) Delete(name string) error {
	if err := validateProfileName(name); err != nil {
		return err
	}
	if name == DefaultProfile {
		return errors.New("cannot delete the default profile")
	}
	if name == d.ActiveProfile {
		return errors.New("cannot delete the active profile; select another profile first")
	}
	if _, err := d.profile(name); err != nil {
		return err
	}
	delete(d.Profiles, name)
	return nil
}

// validateStructure deliberately leaves setting values to Effective and Set.
// This keeps healthy profiles and repair commands usable when another is invalid.
func (d *Document) validateStructure() error {
	if _, err := d.profile(d.ActiveProfile); err != nil {
		return err
	}
	for name, profile := range d.Profiles {
		if err := validateProfileName(name); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
		if profile == nil {
			return fmt.Errorf("profile %q must be a JSON object", name)
		}
	}
	return nil
}

// UnmarshalJSON reads profile documents while retaining unknown properties.
func (d *Document) UnmarshalJSON(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	if root == nil {
		return errors.New("config must be a JSON object")
	}
	*d = *DefaultDocument()
	for _, key := range Keys() {
		if _, misplaced := root[key]; misplaced {
			return fmt.Errorf("setting %q belongs inside profiles.<name>", key)
		}
	}
	if value, ok := root["active_profile"]; ok {
		if err := json.Unmarshal(value, &d.ActiveProfile); err != nil {
			return fmt.Errorf("active_profile must be a string: %w", err)
		}
		if string(value) == "null" || d.ActiveProfile == "" {
			return errors.New("active_profile must be a non-empty string")
		}
		delete(root, "active_profile")
	}
	if value, ok := root["profiles"]; ok {
		if err := json.Unmarshal(value, &d.Profiles); err != nil {
			return fmt.Errorf("profiles must be a JSON object: %w", err)
		}
		if d.Profiles == nil {
			return errors.New("profiles must be a JSON object")
		}
		if _, ok := d.Profiles[DefaultProfile]; !ok {
			d.Profiles[DefaultProfile] = Overrides{}
		}
		delete(root, "profiles")
	}
	d.extra = root
	return d.validateStructure()
}

// MarshalJSON retains unknown top-level metadata as well as profile overrides.
func (d Document) MarshalJSON() ([]byte, error) {
	root := make(map[string]json.RawMessage, len(d.extra)+2)
	for key, value := range d.extra {
		root[key] = value
	}
	active, err := json.Marshal(d.ActiveProfile)
	if err != nil {
		return nil, err
	}
	profiles, err := json.Marshal(d.Profiles)
	if err != nil {
		return nil, err
	}
	root["active_profile"], root["profiles"] = active, profiles
	return json.Marshal(root)
}
