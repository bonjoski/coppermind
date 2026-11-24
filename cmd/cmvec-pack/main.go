package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bonjoski/coppermind/pkg/embedding"
)

// cmvec-pack is a zero-CGO offline build tool that converts plain TSV or JSONL token embeddings
// (e.g. exported from HuggingFace minishlab/potion-base-8M / Model2Vec via scripts/export_model2vec.py)
// into a cryptographically verified, int8-quantized CMVEC1 binary pack.
//
// Supported input formats:
//   - jsonl: {"token":"auth","vector":[0.12,-0.04,...]} per line
//   - tsv:   <token>\t<v0> <v1> ... <vN> per line
func main() {
	inPath := flag.String("in", "", "Input embeddings file (.jsonl or .tsv)")
	outPath := flag.String("out", "model.cmvec", "Output CMVEC1 binary pack path")
	format := flag.String("format", "jsonl", "Input format: jsonl or tsv")
	maxVocab := flag.Int("max-vocab", embedding.MaxCMVEC1VocabSize, "Maximum vocabulary entries to pack")
	flag.Parse()

	if strings.TrimSpace(*inPath) == "" {
		fmt.Fprintln(os.Stderr, "Usage: cmvec-pack --in <embeddings.jsonl|tsv> --out <model.cmvec> [--format jsonl|tsv]")
		os.Exit(1)
	}
	if *maxVocab <= 0 || *maxVocab > embedding.MaxCMVEC1VocabSize {
		*maxVocab = embedding.MaxCMVEC1VocabSize
	}

	f, err := os.Open(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening input %s: %v\n", *inPath, err)
		os.Exit(1)
	}
	defer f.Close()

	var tokens []string
	var vectors [][]float32
	dim := 0
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 128*1024), 8*1024*1024)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(tokens) >= *maxVocab {
			break
		}

		var tok string
		var vec []float32

		switch strings.ToLower(*format) {
		case "jsonl":
			var rec struct {
				Token  string    `json:"token"`
				Vector []float32 `json:"vector"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSONL line %d: %v\n", lineNo, err)
				os.Exit(1)
			}
			tok = strings.ToLower(strings.TrimSpace(rec.Token))
			vec = rec.Vector

		case "tsv":
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 {
				continue
			}
			tok = strings.ToLower(strings.TrimSpace(parts[0]))
			fields := strings.Fields(parts[1])
			vec = make([]float32, len(fields))
			for i, fs := range fields {
				val, err := strconv.ParseFloat(fs, 32)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error parsing float on line %d col %d: %v\n", lineNo, i, err)
					os.Exit(1)
				}
				vec[i] = float32(val)
			}

		default:
			fmt.Fprintf(os.Stderr, "Unsupported format %q (expected jsonl or tsv)\n", *format)
			os.Exit(1)
		}

		if tok == "" || len(tok) > embedding.MaxCMVEC1TokenBytes || seen[tok] || len(vec) == 0 {
			continue
		}
		if dim == 0 {
			dim = len(vec)
		} else if len(vec) != dim {
			fmt.Fprintf(os.Stderr, "Dimension mismatch on line %d: got %d, expected %d\n", lineNo, len(vec), dim)
			os.Exit(1)
		}
		seen[tok] = true
		tokens = append(tokens, tok)
		vectors = append(vectors, vec)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	sum, err := embedding.SaveCMVEC1(*outPath, dim, tokens, vectors)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving CMVEC1 pack: %v\n", err)
		os.Exit(1)
	}

	// Self-verify round-trip before reporting success
	emb, err := embedding.LoadStaticEmbedder(*outPath, sum)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Self-verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Packed verified CMVEC1 static model\n  • Output: %s\n  • Vocab:  %d tokens\n  • Dim:    %d\n  • SHA256: %s\n",
		*outPath, emb.VocabSize(), emb.Dimension(), sum)
}
