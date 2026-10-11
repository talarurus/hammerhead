package fs

import "sort"

// Policy describes defaults and overrides without opening any target path.
func (c *WalkerConfig) Policy() ([]string, map[string]int64) {
	excluded := make(map[string]bool, len(defaultExcludedDirs))
	for name := range defaultExcludedDirs {
		excluded[name] = true
	}
	if c != nil {
		for _, name := range c.ExtraDirs {
			excluded[name] = true
		}
		for _, pattern := range c.ExcludePatterns {
			excluded[pattern] = true
		}
	}
	patterns := make([]string, 0, len(excluded))
	for pattern := range excluded {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	return patterns, map[string]int64{
		"max_depth":                      int64(c.maxDepth()),
		"max_retained_inventory_entries": int64(c.maxFiles()),
		"directory_batch_entries":        int64(c.directoryReadBatch()),
		"max_names_per_directory":        int64(c.maxDirectoryWidth()),
		"max_examined_entries":           int64(c.maxExaminedEntries()),
		"max_native_read_bytes":          c.maxFileSize(),
		"symlink_resolution_steps":       40,
	}
}
