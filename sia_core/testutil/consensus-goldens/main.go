package main

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"go.sia.tech/core/types"
)

func fill(dst []byte, seed byte) {
	for i := range dst {
		dst[i] = seed + byte(i)*37
	}
}

func hash256(seed byte) (h types.Hash256)       { fill(h[:], seed); return }
func address(seed byte) (a types.Address)       { fill(a[:], seed); return }
func publicKey(seed byte) (pk types.PublicKey)  { fill(pk[:], seed); return }
func signature(seed byte) (sig types.Signature) { fill(sig[:], seed); return }

func encode(v types.EncoderTo) string {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	v.EncodeTo(e)
	if err := e.Flush(); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf.Bytes())
}

// writeGroup writes one compact JSON case per line.
func writeGroup(buf *bytes.Buffer, name string, cases any, last bool) {
	data, err := json.Marshal(cases)
	if err != nil {
		panic(err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		panic(err)
	}
	fmt.Fprintf(buf, "%q: [\n", name)
	for i, item := range items {
		buf.Write(item)
		if i < len(items)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteByte(']')
	if !last {
		buf.WriteByte(',')
	}
	buf.WriteByte('\n')
}

func main() {
	output := flag.String("output", "../../testdata/consensus.json.gz", "golden fixture path")
	flag.Parse()
	groups := []struct {
		name  string
		cases any
	}{
		{"networks", networkVectors()},
		{"ids", idVectors()},
		{"v1", v1Vectors()},
		{"v2", v2Vectors()},
		{"policies", policyVectors()},
		{"rhp4", rhp4Vectors()},
	}
	var buf bytes.Buffer
	buf.WriteString("{\n")
	for i, group := range groups {
		writeGroup(&buf, group.name, group.cases, i == len(groups)-1)
	}
	buf.WriteString("}\n")
	if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
		panic(err)
	}
	f, err := os.Create(*output)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		panic(err)
	}
	if _, err := zw.Write(buf.Bytes()); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
}
