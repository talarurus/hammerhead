//go:build !darwin && !linux

package fs

import "fmt"

func watchNamespace(path string) (namespaceWatch, error) {
	return nil, fmt.Errorf("root namespace observation is not supported on this platform")
}
