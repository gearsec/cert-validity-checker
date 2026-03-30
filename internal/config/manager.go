package config

import (
	"errors"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

// Manager handles configuration loading and registration.
type Manager struct {
	v     *viper.Viper
	items []Item
}

// NewManager creates a new configuration manager.
// Environment variables are read with the CERTCHECKER_ prefix;
// dots in keys are replaced with underscores (e.g. slack.webhook_url -> CERTCHECKER_SLACK_WEBHOOK_URL).
func NewManager() *Manager {
	v := viper.New()
	v.SetEnvPrefix("CERTCHECKER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	return &Manager{v: v}
}

// Register registers configuration items with the manager and sets their defaults.
func (m *Manager) Register(prefix string, items ...Item) {
	for _, item := range items {
		if prefix != "" {
			item.Key = prefix + "." + item.Key
		}
		m.items = append(m.items, item)
		if item.DefaultValue != nil {
			m.v.SetDefault(item.Key, item.DefaultValue)
		}
	}
}

// Load reads configuration from a file named "config" in the current directory
// or /etc/certchecker/, then unmarshals into cfg.
// A missing config file is not an error — defaults and env vars are used instead.
func (m *Manager) Load(cfg interface{}) error {
	m.v.SetConfigName("config")
	m.v.AddConfigPath(".")
	m.v.AddConfigPath("/etc/certchecker/")
	if err := m.v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	return m.v.Unmarshal(cfg)
}

// LoadFile reads configuration from the specific file at path, then unmarshals
// into cfg. If the file does not exist the manager falls back to defaults and
// environment variables without returning an error.
func (m *Manager) LoadFile(path string, cfg interface{}) error {
	m.v.SetConfigFile(path)
	if err := m.v.ReadInConfig(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok && !isNotFound(err) {
				return err
			}
		}
	}
	return m.v.Unmarshal(cfg)
}

// RegisterStruct introspects cfg via reflection and registers all exported fields
// as configuration items using their mapstructure tags.
// Fields may carry a `default:"value"` struct tag to set a default.
func (m *Manager) RegisterStruct(cfg interface{}) {
	m.registerStructRecursive("", reflect.TypeOf(cfg))
}

func (m *Manager) registerStructRecursive(prefix string, t reflect.Type) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue // skip unexported
		}

		tag := field.Tag.Get("mapstructure")
		key := tag
		if idx := strings.Index(tag, ","); idx != -1 {
			key = tag[:idx]
		}

		fullKey := key
		if prefix != "" {
			if key != "" {
				fullKey = prefix + "." + key
			} else {
				fullKey = prefix
			}
		}

		if val, ok := field.Tag.Lookup("default"); ok {
			m.v.SetDefault(fullKey, val)
			m.items = append(m.items, Item{Key: fullKey, DefaultValue: val})
		} else {
			m.v.SetDefault(fullKey, nil)
		}

		fieldType := field.Type
		if fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() == reflect.Struct {
			m.registerStructRecursive(fullKey, fieldType)
		}
	}
}

// isNotFound checks whether a viper read error indicates a missing file.
func isNotFound(err error) bool {
	return strings.Contains(err.Error(), "no such file") ||
		strings.Contains(err.Error(), "cannot find") ||
		strings.Contains(err.Error(), "not found")
}
