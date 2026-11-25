package capsule

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/graph"
	"github.com/bonjoski/coppermind/pkg/security"
	"github.com/bonjoski/coppermind/pkg/storage"
)

const (
	// CartridgeSchemaV2 identifies a selective, mergeable Ed25519 knowledge cartridge.
	CartridgeSchemaV2 = "cm-cartridge-v2"

	// MaxCartridgeDecompressedBytes caps decompressed tar+gzip stream at 50 MiB (anti-zip-bomb).
	MaxCartridgeDecompressedBytes = 50 * 1024 * 1024
)

var (
	ErrCartridgeUnsigned        = errors.New("cartridge security violation: unsigned cartridge rejected fail-closed (pass --allow-unsigned for local migration)")
	ErrCartridgeSignatureFailed = errors.New("cartridge security violation: Ed25519 signature verification failed")
	ErrCartridgeMerkleMismatch  = errors.New("cartridge integrity failure: Merkle root mismatch")
	ErrCartridgeUnsafeArchive   = errors.New("cartridge security violation: illegal tar entry or path traversal")
)

// CartridgeManifest describes a selective, mergeable knowledge cartridge (.capsule v2).
type CartridgeManifest struct {
	SchemaVersion string    `json:"schema_version"`
	Name          string    `json:"name"`
	ExportedAt    time.Time `json:"exported_at"`
	RecordCount   int       `json:"record_count"`
	EdgeCount     int       `json:"edge_count"`
	MerkleRoot    string    `json:"merkle_root"`
	Signature     string    `json:"signature,omitempty"`
	PublicKey     string    `json:"public_key,omitempty"`
	FilterRepo    string    `json:"filter_repo,omitempty"`
	FilterCat     string    `json:"filter_category,omitempty"`
	FilterTier    string    `json:"filter_tier,omitempty"`
}

// CartridgeRecord is a portable, sanitized memory record stored in records.jsonl.
type CartridgeRecord struct {
	OriginalID    string            `json:"original_id"`
	Category      string            `json:"category"`
	Content       string            `json:"content"`
	ContentSHA256 string            `json:"content_sha256"`
	AuthorityTier string            `json:"authority_tier"`
	AdvisoryRef   string            `json:"advisory_ref,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
}

// CartridgeExportOptions selects which memories to pack into a mergeable cartridge.
type CartridgeExportOptions struct {
	Name       string
	Repo       string
	Category   string
	Tier       string
	Since      *time.Time
	PrivateKey ed25519.PrivateKey
}

// CartridgeMergeOptions governs fail-closed signature/sanitization verification during merge.
type CartridgeMergeOptions struct {
	RequiredPubKey ed25519.PublicKey
	AllowUnsigned  bool
	SessionID      string
}

// CartridgeMergeResult summarizes a non-destructive cartridge merge into an existing vault.
type CartridgeMergeResult struct {
	Manifest         *CartridgeManifest `json:"manifest"`
	ImportedCount    int                `json:"imported_count"`
	DeduplicatedSkip int                `json:"deduplicated_skip"`
	QuarantinedSkip  int                `json:"quarantined_skip"`
	EdgesRestored    int                `json:"edges_restored"`
	SignedVerified   bool               `json:"signed_verified"`
}

// ExportCartridge packs a filtered subset of active, secret-redacted memories and internal edges
// into a deterministic, Ed25519-signed mergeable .capsule v2 archive (works on both SQLite & Postgres).
func ExportCartridge(ctx context.Context, store storage.CartridgeStore, outPath string, opts CartridgeExportOptions) (*CartridgeManifest, error) {
	if store == nil {
		return nil, fmt.Errorf("cartridge store is required")
	}
	if err := checkNoSymlinkPath(outPath); err != nil {
		return nil, err
	}

	nodes, err := store.QueryActiveNodesForCartridge(ctx, opts.Repo, opts.Category, opts.Tier, opts.Since)
	if err != nil {
		return nil, err
	}

	var records []CartridgeRecord
	idSet := make(map[string]bool)

	for _, n := range nodes {
		// Defense-in-depth: re-sanitize before export so raw secrets can never leave the vault.
		secRes, secErr := security.SanitizeMemory(n.Content)
		if secErr != nil {
			continue
		}
		clean := secRes.SanitizedText
		sum := sha256.Sum256([]byte(clean))
		records = append(records, CartridgeRecord{
			OriginalID:    n.ID,
			Category:      n.Category,
			Content:       clean,
			ContentSHA256: hex.EncodeToString(sum[:]),
			AuthorityTier: n.AuthorityTier,
			AdvisoryRef:   n.AdvisoryRef,
			Metadata:      n.Metadata,
			CreatedAt:     n.CreatedAt.UTC(),
		})
		idSet[n.ID] = true
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].ContentSHA256 < records[j].ContentSHA256
	})

	var recBuf bytes.Buffer
	merkleHasher := sha256.New()
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		recBuf.Write(line)
		recBuf.WriteByte('\n')
		merkleHasher.Write([]byte(r.ContentSHA256))
	}

	// Collect internal edges among exported nodes
	var edges []graph.Edge
	if graphStore, ok := store.(storage.GraphStore); ok {
		for id := range idSet {
			nodeEdges, err := graphStore.GetEdgesForNode(ctx, id)
			if err != nil {
				continue
			}
			for _, e := range nodeEdges {
				if e.SourceID == id && (e.TargetID == "" || idSet[e.TargetID]) {
					edges = append(edges, e)
				}
			}
		}
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	var edgeBuf bytes.Buffer
	for _, e := range edges {
		line, _ := json.Marshal(e)
		edgeBuf.Write(line)
		edgeBuf.WriteByte('\n')
	}

	merkleRoot := hex.EncodeToString(merkleHasher.Sum(nil))
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(outPath), filepath.Ext(outPath))
	}

	manifest := &CartridgeManifest{
		SchemaVersion: CartridgeSchemaV2,
		Name:          name,
		ExportedAt:    time.Now().UTC(),
		RecordCount:   len(records),
		EdgeCount:     len(edges),
		MerkleRoot:    merkleRoot,
		FilterRepo:    opts.Repo,
		FilterCat:     opts.Category,
		FilterTier:    opts.Tier,
	}

	if len(opts.PrivateKey) == ed25519.PrivateKeySize {
		sigPayload := cartridgeSigPayload(manifest)
		sig := ed25519.Sign(opts.PrivateKey, sigPayload)
		manifest.Signature = hex.EncodeToString(sig)
		pub := opts.PrivateKey.Public().(ed25519.PublicKey)
		manifest.PublicKey = hex.EncodeToString(pub)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return nil, err
	}
	tmpPath := outPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	if err := writeTarEntry(tw, "manifest.json", manifestBytes); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := writeTarEntry(tw, "records.jsonl", recBuf.Bytes()); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := writeTarEntry(tw, "edges.jsonl", edgeBuf.Bytes()); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := tw.Close(); err != nil {
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := gw.Close(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	return manifest, nil
}

// MergeCartridge verifies tar-slip, size caps (50MB), Merkle root, Ed25519 signature, and
// Stormcage cognitive/secret quarantine before non-destructively merging records into mgr.
func MergeCartridge(ctx context.Context, mgr *brain.Manager, capsulePath string, opts CartridgeMergeOptions) (*CartridgeMergeResult, error) {
	if mgr == nil {
		return nil, fmt.Errorf("brain manager is required")
	}
	if err := checkNoSymlinkPath(capsulePath); err != nil {
		return nil, err
	}

	inFile, err := os.Open(capsulePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening cartridge: %w", err)
	}
	defer inFile.Close()

	gr, err := gzip.NewReader(inFile)
	if err != nil {
		return nil, fmt.Errorf("invalid gzip cartridge: %w", err)
	}
	defer gr.Close()

	// Anti-zip-bomb hard decompressed limit (50 MiB)
	limited := io.LimitReader(gr, MaxCartridgeDecompressedBytes+1)
	tr := tar.NewReader(limited)

	var manifest *CartridgeManifest
	var recordsRaw, edgesRaw []byte
	var totalBytes int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("corrupted tar cartridge: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: non-regular tar entry %q (type %d)", ErrCartridgeUnsafeArchive, hdr.Name, hdr.Typeflag)
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) || strings.Contains(clean, string(filepath.Separator)+"..") {
			return nil, fmt.Errorf("%w: illegal path %q", ErrCartridgeUnsafeArchive, hdr.Name)
		}

		data, err := io.ReadAll(io.LimitReader(tr, MaxCartridgeDecompressedBytes-totalBytes+1))
		if err != nil {
			return nil, err
		}
		totalBytes += int64(len(data))
		if totalBytes > MaxCartridgeDecompressedBytes {
			return nil, fmt.Errorf("%w: decompressed cartridge exceeds %d bytes", ErrCartridgeUnsafeArchive, MaxCartridgeDecompressedBytes)
		}

		switch clean {
		case "manifest.json":
			manifest = &CartridgeManifest{}
			if err := json.Unmarshal(data, manifest); err != nil {
				return nil, fmt.Errorf("corrupted cartridge manifest: %w", err)
			}
		case "records.jsonl":
			recordsRaw = data
		case "edges.jsonl":
			edgesRaw = data
		}
	}

	if manifest == nil || manifest.SchemaVersion != CartridgeSchemaV2 {
		return nil, fmt.Errorf("invalid cartridge: missing or unsupported schema_version")
	}

	// 1. Parse records & verify deterministic Merkle root
	var records []CartridgeRecord
	merkleHasher := sha256.New()
	scanner := bufio.NewScanner(bytes.NewReader(recordsRaw))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec CartridgeRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("corrupted cartridge record: %w", err)
		}
		sum := sha256.Sum256([]byte(rec.Content))
		actualSHA := hex.EncodeToString(sum[:])
		if rec.ContentSHA256 != "" && rec.ContentSHA256 != actualSHA {
			return nil, fmt.Errorf("%w: record content hash mismatch", ErrCartridgeMerkleMismatch)
		}
		rec.ContentSHA256 = actualSHA
		merkleHasher.Write([]byte(actualSHA))
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	actualRoot := hex.EncodeToString(merkleHasher.Sum(nil))
	if actualRoot != manifest.MerkleRoot || len(records) != manifest.RecordCount {
		return nil, fmt.Errorf("%w: expected %s (%d records), got %s (%d records)",
			ErrCartridgeMerkleMismatch, manifest.MerkleRoot, manifest.RecordCount, actualRoot, len(records))
	}

	// 2. Verify Ed25519 signature fail-closed
	signedVerified := false
	if manifest.Signature == "" {
		if !opts.AllowUnsigned || len(opts.RequiredPubKey) == ed25519.PublicKeySize {
			return nil, ErrCartridgeUnsigned
		}
	} else {
		pub := opts.RequiredPubKey
		if len(pub) != ed25519.PublicKeySize {
			decodedPub, err := hex.DecodeString(manifest.PublicKey)
			if err != nil || len(decodedPub) != ed25519.PublicKeySize {
				return nil, ErrCartridgeSignatureFailed
			}
			pub = ed25519.PublicKey(decodedPub)
		}
		sigBytes, err := hex.DecodeString(manifest.Signature)
		if err != nil || !ed25519.Verify(pub, cartridgeSigPayload(manifest), sigBytes) {
			return nil, ErrCartridgeSignatureFailed
		}
		signedVerified = true
	}

	// 3. Load existing content_sha256 set for fast deduplication (works on SQLite & Postgres)
	existingHashes := make(map[string]bool)
	if capStore, ok := mgr.Store().(storage.CartridgeStore); ok {
		if loaded, err := capStore.ListExistingContentHashes(ctx); err == nil {
			existingHashes = loaded
		}
	}
	graphStore, hasGraph := mgr.Store().(storage.GraphStore)

	sessionID := strings.TrimSpace(opts.SessionID)
	if sessionID == "" {
		sessionID = "cartridge:" + manifest.Name
	}

	res := &CartridgeMergeResult{
		Manifest:       manifest,
		SignedVerified: signedVerified,
	}

	idRemap := make(map[string]string, len(records))
	for _, rec := range records {
		if existingHashes[rec.ContentSHA256] {
			res.DeduplicatedSkip++
			continue
		}

		// Security gate: quarantine raw private keys & critical prompt injections even inside signed packs!
		secRes, secErr := security.SanitizeMemory(rec.Content)
		if secErr != nil {
			res.QuarantinedSkip++
			continue
		}
		if threat, tErr := security.InspectCognitiveThreats(secRes.SanitizedText); tErr == nil && threat != nil && threat.IsCritical {
			res.QuarantinedSkip++
			continue
		}

		tier := rec.AuthorityTier
		lifecycle := string(authz.StatusActive)
		if !signedVerified {
			// Unsigned local merges are strictly capped at TIER_2_MENTOR_CAPSULE / PROPOSED.
			tier = authz.TierName2MentorCapsule
			lifecycle = string(authz.StatusProposed)
		} else if tier == authz.TierName0Sovereign {
			// Never silently elevate imported cartridges to TIER_0_SOVEREIGN.
			tier = authz.TierName1Architecture
		}

		meta := make(map[string]string, len(rec.Metadata)+2)
		for k, v := range rec.Metadata {
			meta[k] = v
		}
		meta["cartridge_name"] = manifest.Name
		meta["cartridge_merkle"] = manifest.MerkleRoot

		stored, err := mgr.Remember(ctx, brain.RememberRequest{
			SessionID:       sessionID,
			Category:        rec.Category,
			Content:         secRes.SanitizedText,
			Provenance:      brain.ProvenanceLocalWorkspace,
			AuthorityTier:   tier,
			LifecycleStatus: lifecycle,
			AdvisoryRef:     rec.AdvisoryRef,
			Metadata:        meta,
		})
		if err != nil {
			res.QuarantinedSkip++
			continue
		}
		existingHashes[rec.ContentSHA256] = true
		idRemap[rec.OriginalID] = stored.ID
		res.ImportedCount++
	}

	// 4. Restore internal edges for remapped nodes
	if hasGraph && len(edgesRaw) > 0 && len(idRemap) > 0 {
		var restored []graph.Edge
		es := bufio.NewScanner(bytes.NewReader(edgesRaw))
		for es.Scan() {
			line := strings.TrimSpace(es.Text())
			if line == "" {
				continue
			}
			var e graph.Edge
			if json.Unmarshal([]byte(line), &e) != nil || !graph.IsValidRelation(e.Relation) {
				continue
			}
			newSrc, ok := idRemap[e.SourceID]
			if !ok {
				continue
			}
			newTgt := ""
			if e.TargetID != "" {
				if mapped, ok2 := idRemap[e.TargetID]; ok2 {
					newTgt = mapped
				} else {
					continue
				}
			}
			sum := sha256.Sum256([]byte(newSrc + ":" + string(e.Relation) + ":" + newTgt + ":" + e.TargetEntity))
			restored = append(restored, graph.Edge{
				ID:           "edge_" + hex.EncodeToString(sum[:8]),
				SourceID:     newSrc,
				TargetID:     newTgt,
				TargetEntity: e.TargetEntity,
				Relation:     e.Relation,
				Weight:       e.Weight,
				Derived:      e.Derived,
				CreatedAt:    time.Now(),
			})
		}
		if len(restored) > 0 && graphStore.StoreEdges(ctx, restored) == nil {
			res.EdgesRestored = len(restored)
		}
	}

	return res, nil
}

func cartridgeSigPayload(m *CartridgeManifest) []byte {
	return []byte(fmt.Sprintf("%s:%s:%s:%d:%d", m.SchemaVersion, m.Name, m.MerkleRoot, m.RecordCount, m.EdgeCount))
}

// CartridgeInspectResult summarizes an offline, read-only audit of a .capsule v2 cartridge.
type CartridgeInspectResult struct {
	Manifest       *CartridgeManifest `json:"manifest"`
	MerkleValid    bool               `json:"merkle_valid"`
	Signed         bool               `json:"signed"`
	SignatureValid bool               `json:"signature_valid"`
	SampleRecords  []CartridgeRecord  `json:"sample_records,omitempty"`
	EdgeCount      int                `json:"edge_count"`
}

// InspectCartridge performs an offline, read-only integrity & provenance inspection of a
// mergeable .capsule v2 cartridge without touching any SQLite database.
func InspectCartridge(capsulePath string, requiredPubKey ed25519.PublicKey) (*CartridgeInspectResult, error) {
	if err := checkNoSymlinkPath(capsulePath); err != nil {
		return nil, err
	}
	inFile, err := os.Open(capsulePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening cartridge: %w", err)
	}
	defer inFile.Close()

	gr, err := gzip.NewReader(inFile)
	if err != nil {
		return nil, fmt.Errorf("invalid gzip cartridge: %w", err)
	}
	defer gr.Close()

	limited := io.LimitReader(gr, MaxCartridgeDecompressedBytes+1)
	tr := tar.NewReader(limited)

	var manifest *CartridgeManifest
	var recordsRaw, edgesRaw []byte
	var totalBytes int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("corrupted tar cartridge: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: non-regular tar entry %q (type %d)", ErrCartridgeUnsafeArchive, hdr.Name, hdr.Typeflag)
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) || strings.Contains(clean, string(filepath.Separator)+"..") {
			return nil, fmt.Errorf("%w: illegal path %q", ErrCartridgeUnsafeArchive, hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxCartridgeDecompressedBytes-totalBytes+1))
		if err != nil {
			return nil, err
		}
		totalBytes += int64(len(data))
		if totalBytes > MaxCartridgeDecompressedBytes {
			return nil, fmt.Errorf("%w: decompressed cartridge exceeds %d bytes", ErrCartridgeUnsafeArchive, MaxCartridgeDecompressedBytes)
		}
		switch clean {
		case "manifest.json":
			manifest = &CartridgeManifest{}
			if err := json.Unmarshal(data, manifest); err != nil {
				return nil, fmt.Errorf("corrupted cartridge manifest: %w", err)
			}
		case "records.jsonl":
			recordsRaw = data
		case "edges.jsonl":
			edgesRaw = data
		}
	}

	if manifest == nil || manifest.SchemaVersion != CartridgeSchemaV2 {
		return nil, fmt.Errorf("invalid cartridge: missing or unsupported schema_version")
	}

	var samples []CartridgeRecord
	merkleHasher := sha256.New()
	recCount := 0
	scanner := bufio.NewScanner(bytes.NewReader(recordsRaw))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec CartridgeRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("corrupted cartridge record: %w", err)
		}
		sum := sha256.Sum256([]byte(rec.Content))
		actualSHA := hex.EncodeToString(sum[:])
		if rec.ContentSHA256 != "" && rec.ContentSHA256 != actualSHA {
			return nil, fmt.Errorf("%w: record content hash mismatch", ErrCartridgeMerkleMismatch)
		}
		rec.ContentSHA256 = actualSHA
		merkleHasher.Write([]byte(actualSHA))
		recCount++
		if len(samples) < 5 {
			samples = append(samples, rec)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	actualRoot := hex.EncodeToString(merkleHasher.Sum(nil))
	merkleOK := actualRoot == manifest.MerkleRoot && recCount == manifest.RecordCount

	edgeCount := 0
	if len(edgesRaw) > 0 {
		es := bufio.NewScanner(bytes.NewReader(edgesRaw))
		for es.Scan() {
			if strings.TrimSpace(es.Text()) != "" {
				edgeCount++
			}
		}
	}

	res := &CartridgeInspectResult{
		Manifest:      manifest,
		MerkleValid:   merkleOK,
		Signed:        manifest.Signature != "",
		SampleRecords: samples,
		EdgeCount:     edgeCount,
	}

	if manifest.Signature != "" {
		pub := requiredPubKey
		if len(pub) != ed25519.PublicKeySize {
			decoded, err := hex.DecodeString(manifest.PublicKey)
			if err == nil && len(decoded) == ed25519.PublicKeySize {
				pub = ed25519.PublicKey(decoded)
			}
		}
		if len(pub) == ed25519.PublicKeySize {
			if sigBytes, err := hex.DecodeString(manifest.Signature); err == nil {
				res.SignatureValid = ed25519.Verify(pub, cartridgeSigPayload(manifest), sigBytes)
			}
		}
	}

	if !res.MerkleValid {
		return res, fmt.Errorf("%w: expected %s (%d records), got %s (%d records)",
			ErrCartridgeMerkleMismatch, manifest.MerkleRoot, manifest.RecordCount, actualRoot, recCount)
	}
	if len(requiredPubKey) == ed25519.PublicKeySize && !res.SignatureValid {
		return res, ErrCartridgeSignatureFailed
	}
	return res, nil
}
