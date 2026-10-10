package fs_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/fs"
)

func TestWalk_DeterministicBoundedSamples(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	for _, mode := range []string{"completed", "width-cap", "examined-cap"} {
		t.Run(mode, func(t *testing.T) {
			var want []fs.SkippedEntry
			for run := 0; run < 24; run++ {
				root := t.TempDir()
				names := []string{}
				for i := 0; i < 12; i++ {
					names = append(names, fmt.Sprintf("%02d.omit", i))
				}
				rng.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
				for _, name := range names {
					if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				config := &fs.WalkerConfig{ExcludePatterns: []string{"*.omit"}, MaxSkippedEntries: 4, MaxExamplesPerReason: 2, DirectoryReadBatch: 3}
				if mode == "width-cap" {
					config.MaxDirectoryWidth = 10
				}
				if mode == "examined-cap" {
					config.MaxExaminedEntries = 10
				}
				walker, err := fs.NewSafeWalker(root, config)
				if err != nil {
					t.Fatal(err)
				}
				files, inv, err := walker.Walk(context.Background())
				if len(files) != 1 || files[0].Path != "." {
					t.Fatalf("unexpected retained prefix: %+v", files)
				}
				if mode == "completed" {
					if err != nil || !inv.InventoryComplete || !inv.RootListComplete {
						t.Fatalf("expected complete listing: %v %+v", err, inv)
					}
					got := walker.Skipped()
					if len(got) != 2 || got[0].Path != "00.omit" || got[1].Path != "01.omit" || walker.SkippedOmitted() != 10 {
						t.Fatalf("wrong bounded samples: %+v, omitted %d", got, walker.SkippedOmitted())
					}
				} else {
					if !errors.Is(err, fs.ErrBudgetExhausted) || inv.InventoryComplete || inv.RootListComplete {
						t.Fatalf("overflow must be incomplete: %v %+v", err, inv)
					}
					if inv.ExaminedEntries != 11 || len(walker.Skipped()) != 1 || walker.Skipped()[0].Path != "." {
						t.Fatalf("overflow must discard unprocessed child set: %+v %+v", inv, walker.Skipped())
					}
				}
				got := walker.Skipped()
				if run == 0 {
					want = got
				} else if !reflect.DeepEqual(got, want) {
					t.Fatalf("creation shuffle %d changed retained samples: %+v; want %+v", run, got, want)
				}
			}
		})
	}
}
