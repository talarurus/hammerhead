package git

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"strings"
)

// This is an admission-only envelope walk, not an index truth parser. It
// produces no paths, modes, status or object facts. Git still validates the
// checksum, entry/path encodings and cache tree. Unknown optional extensions
// otherwise silently ignored by Git must be refused before status.
func admitIndexEnvelope(data []byte) error {
	if len(data) < 32 || string(data[:4]) != "DIRC" {
		return refuse("index envelope")
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version < 2 || version > 4 {
		return refuse("index version")
	}
	count := binary.BigEndian.Uint32(data[8:12])
	if count > metadataEntries {
		return refuse("index entry budget")
	}
	end := len(data) - 20
	checksum := sha1.Sum(data[:end])
	if !bytes.Equal(checksum[:], data[end:]) {
		return refuse("index checksum")
	}
	pos := 12
	for i := uint32(0); i < count; i++ {
		start := pos
		if pos > end-62 {
			return refuse("index framing")
		}
		flags := binary.BigEndian.Uint16(data[pos+60 : pos+62])
		pos += 62
		if flags&0x8000 != 0 {
			return refuse("assume unchanged index")
		}
		if flags&0x4000 != 0 {
			if version == 2 || pos > end-2 {
				return refuse("index extended flags")
			}
			if binary.BigEndian.Uint16(data[pos:pos+2]) != 0 {
				return refuse("unsupported index flags")
			}
			pos += 2
		}
		if version == 4 {
			// Prefix-compression varint: only find the bounded entry frame. Git
			// owns decoding and validates the actual path-prefix arithmetic.
			for n := 0; ; n++ {
				if n >= 10 || pos >= end {
					return refuse("index path framing")
				}
				c := data[pos]
				pos++
				if c&0x80 == 0 {
					break
				}
			}
		}
		nul := bytes.IndexByte(data[pos:end], 0)
		if nul < 0 {
			return refuse("index path framing")
		}
		pos += nul + 1
		if version != 4 {
			pos = start + ((pos - start + 7) &^ 7)
		}
		if pos > end {
			return refuse("index framing")
		}
	}
	seenTree := false
	for pos < end {
		if end-pos < 8 {
			return refuse("index extension framing")
		}
		signature := string(data[pos : pos+4])
		n := uint64(binary.BigEndian.Uint32(data[pos+4 : pos+8]))
		pos += 8
		if n > uint64(end-pos) {
			return refuse("index extension framing")
		}
		// TREE is Git's ordinary cache-tree optimization. Split/sparse,
		// fsmonitor, untracked cache and all other extensions are unsupported.
		if signature != "TREE" || seenTree {
			return refuse("unsupported index extension")
		}
		seenTree = true
		pos += int(n)
	}
	return nil
}

func admitIndexListing(out string) error {
	if out != "" && !strings.HasSuffix(out, "\x00") {
		return refuse("index listing framing")
	}
	for _, rec := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
		if rec == "" {
			continue
		}
		// -v tag, mode, SHA-1, stage, TAB, raw path. Only ordinary cache
		// entries are admitted; neither a subdirectory cwd nor a sparse index
		// can hide a gitlink or an ignored/assume-unchanged entry.
		if len(rec) < 53 || rec[0] != 'H' || rec[1] != ' ' || rec[8] != ' ' || rec[49] != ' ' || rec[51] != '\t' || !strings.Contains("0123", rec[50:51]) {
			return refuse("index mode or flags")
		}
		if rec[2:8] != "100644" && rec[2:8] != "100755" && rec[2:8] != "120000" {
			return refuse("index mode or flags")
		}
		if strings.Trim(rec[9:49], "0123456789abcdef") != "" {
			return refuse("index object format")
		}
	}
	return nil
}
