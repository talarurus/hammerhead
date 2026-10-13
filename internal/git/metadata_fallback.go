//go:build !darwin && !linux

package git

import (
	"context"
)

type metadataSource struct{ created []string }

func (*metadataSource) close() error                 { return nil }
func (*metadataSource) verify(context.Context) error { return refuse("unsupported platform") }
func prepareMetadata(context.Context, string, *GitRunner, *metadataBudget) (*metadataView, error) {
	return nil, refuse("unsupported platform")
}
