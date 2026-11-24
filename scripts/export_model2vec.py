#!/usr/bin/env python3
"""
Offline Model2Vec / Potion -> Coppermind CMVEC1 Exporter (Build-Time Only)

Runtime Coppermind is 100% pure Go with zero Python or CGO dependencies.
Use this offline helper to export an open-weights Model2Vec static model
(e.g. minishlab/potion-base-8M) to a verified, int8-quantized CMVEC1 pack:

    pip install model2vec
    python3 scripts/export_model2vec.py \
        --model minishlab/potion-base-8M \
        --out potion-base-8m.cmvec

Install the resulting pack into Coppermind with mandatory SHA-256 verification:

    coppermind models pull potion-base-8m \
        --from-file potion-base-8m.cmvec \
        --sha256 <printed-sha256>
    coppermind reindex-vectors
"""

import argparse
import hashlib
import math
import struct
import sys

MAGIC = b"CMVEC1\x00\x00"
VERSION = 1
QUANT_INT8_SCALE = 1
HEADER_SIZE = 64
MAX_DIM = 1024
MAX_VOCAB = 250000
MAX_TOKEN_BYTES = 256


def export_model2vec(model_id: str, out_path: str, max_vocab: int) -> str:
    try:
        from model2vec import StaticModel
    except ImportError:
        print("Error: install model2vec offline first (`pip install model2vec`).", file=sys.stderr)
        sys.exit(1)

    model = StaticModel.from_pretrained(model_id)
    vocab = model.tokenizer.get_vocab()
    embeddings = model.embedding

    dim = int(embeddings.shape[1])
    if dim <= 0 or dim > MAX_DIM:
        raise ValueError(f"Unsupported embedding dimension {dim} (max {MAX_DIM})")

    # Deterministic token ordering by vocab id
    items = sorted(vocab.items(), key=lambda kv: kv[1])
    seen = set()
    payload = bytearray()
    count = 0

    for token, idx in items:
        if count >= max_vocab:
            break
        norm_tok = token.strip().lower()
        if not norm_tok or norm_tok in seen:
            continue
        tok_bytes = norm_tok.encode("utf-8")
        if len(tok_bytes) == 0 or len(tok_bytes) > MAX_TOKEN_BYTES:
            continue
        vec = embeddings[idx]
        max_abs = float(max(abs(float(x)) for x in vec))
        scale = (max_abs / 127.0) if max_abs > 0.0 else 0.0

        payload.extend(struct.pack("<H", len(tok_bytes)))
        payload.extend(tok_bytes)
        payload.extend(struct.pack("<f", scale))
        for v in vec:
            fv = float(v)
            if not math.isfinite(fv):
                fv = 0.0
            q = 0 if scale == 0.0 else max(-127, min(127, int(round(fv / scale))))
            payload.extend(struct.pack("<b", q))

        seen.add(norm_tok)
        count += 1

    payload_digest = hashlib.sha256(payload).digest()
    header = bytearray(HEADER_SIZE)
    header[0:8] = MAGIC
    struct.pack_into("<I", header, 8, VERSION)
    struct.pack_into("<I", header, 12, dim)
    struct.pack_into("<I", header, 16, count)
    header[20] = QUANT_INT8_SCALE
    header[24:56] = payload_digest

    full_bytes = bytes(header) + bytes(payload)
    file_sha256 = hashlib.sha256(full_bytes).hexdigest()

    with open(out_path, "wb") as f:
        f.write(full_bytes)

    print(f"✓ Exported {model_id} -> {out_path}")
    print(f"  • Vocab:  {count} tokens")
    print(f"  • Dim:    {dim}")
    print(f"  • Size:   {len(full_bytes) / (1024 * 1024):.2f} MiB")
    print(f"  • SHA256: {file_sha256}")
    return file_sha256


def main() -> None:
    parser = argparse.ArgumentParser(description="Export Model2Vec/Potion model to Coppermind CMVEC1 format.")
    parser.add_argument("--model", default="minishlab/potion-base-8M", help="HuggingFace Model2Vec model ID or local path")
    parser.add_argument("--out", default="potion-base-8m.cmvec", help="Output .cmvec file path")
    parser.add_argument("--max-vocab", type=int, default=MAX_VOCAB, help="Maximum vocab size to export")
    args = parser.parse_args()
    export_model2vec(args.model, args.out, min(args.max_vocab, MAX_VOCAB))


if __name__ == "__main__":
    main()
