// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
// This file contains stub implementations. See github.com/careyjames/dnstool-intel for the full version.
package analyzer

type ManifestEntry struct {
	Feature          string
	Category         string
	Description      string
	SchemaKey        string
	DetectionMethods []string
	RFC              string
}

var FeatureParityManifest = []ManifestEntry{}

var RequiredSchemaKeys []string

func init() {}

func GetManifestByCategory(category string) []ManifestEntry {
	var result []ManifestEntry
	for _, entry := range FeatureParityManifest {
		if entry.Category == category {
			result = append(result, entry)
		}
	}
	return result
}
