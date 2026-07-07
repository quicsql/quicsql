package config

import (
	"fmt"
	"sync"

	"go.yaml.in/yaml/v3"
)

// Optional feature modules (compiled into a product binary, not core `cmd/quicsql`)
// own their OWN top-level config section — the Caddy/CoreDNS plugin model applied to
// config. A feature calls RegisterSection(key) from an init(); Load then accepts that
// key (no "unknown top-level key" warning) and captures its raw YAML, which the
// feature decodes into its own typed struct with Config.DecodeSection during setup.
// Core never types a registered section — it stays out of the core config schema.

var (
	sectionMu  sync.Mutex
	registered = map[string]bool{}
)

// RegisterSection declares a top-level config key owned by a feature module. Call it
// from the feature package's init(); a product binary compiles the feature in with a
// blank import. Core registers none.
func RegisterSection(key string) {
	sectionMu.Lock()
	defer sectionMu.Unlock()
	registered[key] = true
}

func sectionRegistered(key string) bool {
	sectionMu.Lock()
	defer sectionMu.Unlock()
	return registered[key]
}

// DecodeSection decodes a registered feature section into dst (a pointer to the
// feature's config struct). It reports whether the section was present; a decode
// failure (malformed YAML for that block) is returned as an error. Validation of the
// decoded values is the feature's own responsibility, in its setup — an error there
// aborts startup before any listener serves, so it is still fail-fast.
func (c *Config) DecodeSection(key string, dst any) (bool, error) {
	node, ok := c.sections[key]
	if !ok {
		return false, nil
	}
	if err := node.Decode(dst); err != nil {
		return false, fmt.Errorf("config: section %q: %w", key, err)
	}
	return true, nil
}

// captureSections records the raw YAML node of every registered top-level section so a
// feature can DecodeSection it later. Called from Load after the file is read.
func (c *Config) captureSections(fileBytes []byte) {
	var nodes map[string]yaml.Node
	if err := yaml.Unmarshal(fileBytes, &nodes); err != nil {
		return // a parse error is already reported by the primary Unmarshal in Load
	}
	for k, node := range nodes {
		if sectionRegistered(k) {
			if c.sections == nil {
				c.sections = map[string]yaml.Node{}
			}
			c.sections[k] = node
		}
	}
}
