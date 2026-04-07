// SPDX-License-Identifier: Apache-2.0

package weaverprocessor

// Config holds the configuration for the Weaver processor.
type Config struct {
	// WASMPath is the path to the weaver_wasm.wasm module.
	WASMPath string `mapstructure:"wasm_path"`

	// PoliciesJSON is an optional inline JSON array of Rego policies.
	// Each element must have "filename" and "content" fields.
	// If empty, no custom policies are loaded.
	PoliciesJSON string `mapstructure:"policies_json"`
}

func (c *Config) Validate() error {
	return nil
}
