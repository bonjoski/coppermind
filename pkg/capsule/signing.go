package capsule

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultPrivateKeyFilename is the canonical private key filename emitted by `capsule keygen`.
	DefaultPrivateKeyFilename = "ed25519.key"

	// DefaultPublicKeyFilename is the canonical public key filename emitted by `capsule keygen`.
	DefaultPublicKeyFilename = "ed25519.pub"

	maxKeyFileBytes = 16 * 1024 // 16KB anti-DoS cap on key files
)

var (
	ErrKeySymlinkRejected = errors.New("capsule key security violation: symlink target refused fail-closed")
	ErrKeyFileExists      = errors.New("capsule key already exists (pass --force to overwrite)")
	ErrInvalidKeyFormat   = errors.New("invalid Ed25519 key format")
)

// KeypairFiles summarizes a newly generated local Ed25519 signing keypair.
type KeypairFiles struct {
	PrivateKeyPath string
	PublicKeyPath  string
	PublicKeyHex   string
	PublicKey      ed25519.PublicKey
	PrivateKey     ed25519.PrivateKey
}

// SignedCapsuleResult reports the outcome of signing or packing a Mentor or Requirements capsule.
type SignedCapsuleResult struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	ItemCount     int    `json:"item_count"`
	MerkleRoot    string `json:"merkle_root"`
	AuthorityTier string `json:"authority_tier"`
	Provenance    string `json:"provenance"`
	PublicKeyHex  string `json:"public_key,omitempty"`
	OutputPath    string `json:"output_path"`
	Format        string `json:"format"` // "capsule" | "json"
}

// VerifiedCapsuleResult reports the outcome of offline verification of a Mentor or Requirements capsule.
type VerifiedCapsuleResult struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	ItemCount     int    `json:"item_count"`
	MerkleRoot    string `json:"merkle_root"`
	AuthorityTier string `json:"authority_tier"`
	Provenance    string `json:"provenance"`
}

func checkNoSymlinkPath(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrKeySymlinkRejected, path)
	}
	return nil
}

// GenerateEd25519Keypair generates a fresh Ed25519 signing keypair inside outDir.
// Private key permissions are enforced atomically as 0600 via os.OpenFile(O_CREATE|O_WRONLY|O_EXCL, 0600).
// Symlinks on outDir or target key paths are always refused fail-closed. Existing keys are refused unless force is true.
func GenerateEd25519Keypair(outDir string, force bool) (*KeypairFiles, error) {
	dir := strings.TrimSpace(outDir)
	if dir == "" {
		return nil, fmt.Errorf("output directory is required")
	}
	cleanDir := filepath.Clean(dir)

	// Refuse symlink output directory fail-closed.
	if fi, err := os.Lstat(cleanDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: output directory %s is a symlink", ErrKeySymlinkRejected, cleanDir)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("output path %s exists and is not a directory", cleanDir)
		}
	} else if os.IsNotExist(err) {
		if mkErr := os.MkdirAll(cleanDir, 0700); mkErr != nil {
			return nil, fmt.Errorf("failed creating key directory %s: %w", cleanDir, mkErr)
		}
	} else {
		return nil, fmt.Errorf("failed inspecting output directory %s: %w", cleanDir, err)
	}

	privPath := filepath.Join(cleanDir, DefaultPrivateKeyFilename)
	pubPath := filepath.Join(cleanDir, DefaultPublicKeyFilename)

	for _, p := range []string{privPath, pubPath} {
		fi, err := os.Lstat(p)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: %s is a symlink", ErrKeySymlinkRejected, p)
			}
			if !fi.Mode().IsRegular() {
				return nil, fmt.Errorf("refusing non-regular file target %s", p)
			}
			if !force {
				return nil, fmt.Errorf("%w: %s", ErrKeyFileExists, p)
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating Ed25519 keypair: %w", err)
	}

	if force {
		// Re-verify non-symlink immediately before removal.
		for _, p := range []string{privPath, pubPath} {
			if err := checkNoSymlinkPath(p); err != nil {
				return nil, err
			}
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed removing existing key %s: %w", p, err)
			}
		}
	}

	privHex := hex.EncodeToString(priv) + "\n"
	pubHex := hex.EncodeToString(pub) + "\n"

	// Create private key atomically with 0600 + O_EXCL so it is never world-readable and never follows a newly raced symlink.
	if err := writeKeyFileExclusive(privPath, []byte(privHex), 0600); err != nil {
		return nil, fmt.Errorf("failed writing private key %s: %w", privPath, err)
	}
	if err := writeKeyFileExclusive(pubPath, []byte(pubHex), 0644); err != nil {
		_ = os.Remove(privPath)
		return nil, fmt.Errorf("failed writing public key %s: %w", pubPath, err)
	}

	return &KeypairFiles{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
		PublicKeyHex:   strings.TrimSpace(pubHex),
		PublicKey:      pub,
		PrivateKey:     priv,
	}, nil
}

func writeKeyFileExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// LoadEd25519PrivateKey loads an Ed25519 private key from either a file path (hex 64-byte key,
// hex 32-byte seed, or PKCS8 PEM) or a direct hex-encoded private key string.
func LoadEd25519PrivateKey(spec string) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: private key path or hex is required", ErrInvalidKeyFormat)
	}

	// Direct hex string support (64-byte private key = 128 hex chars, or 32-byte seed = 64 hex chars)
	if key, ok := tryDecodeEd25519PrivateHex(trimmed); ok {
		return key, nil
	}

	if err := checkNoSymlinkPath(trimmed); err != nil {
		return nil, err
	}
	f, err := os.Open(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open private key file %q: %v", ErrInvalidKeyFormat, trimmed, err)
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: failed reading private key file: %v", ErrInvalidKeyFormat, err)
	}
	if len(raw) > maxKeyFileBytes {
		return nil, fmt.Errorf("%w: private key file exceeds %d bytes", ErrInvalidKeyFormat, maxKeyFileBytes)
	}

	content := strings.TrimSpace(string(raw))
	if key, ok := tryDecodeEd25519PrivateHex(content); ok {
		return key, nil
	}

	if block, _ := pem.Decode(raw); block != nil {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid PKCS8 PEM private key: %v", ErrInvalidKeyFormat, err)
		}
		edKey, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: PEM private key is not Ed25519", ErrInvalidKeyFormat)
		}
		return edKey, nil
	}

	return nil, fmt.Errorf("%w: expected 64-byte hex Ed25519 private key or PKCS8 PEM", ErrInvalidKeyFormat)
}

func tryDecodeEd25519PrivateHex(s string) (ed25519.PrivateKey, bool) {
	if len(s) != ed25519.PrivateKeySize*2 && len(s) != ed25519.SeedSize*2 {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), true
	}
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), true
	}
	return nil, false
}

// LoadEd25519PublicKey loads an Ed25519 public key from either a raw 64-char hex string
// or a local file path containing hex or PKIX PEM.
func LoadEd25519PublicKey(spec string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: public key path or hex is required", ErrInvalidKeyFormat)
	}

	if len(trimmed) == ed25519.PublicKeySize*2 {
		if b, err := hex.DecodeString(trimmed); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}

	if err := checkNoSymlinkPath(trimmed); err != nil {
		return nil, err
	}
	f, err := os.Open(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open public key file %q: %v", ErrInvalidKeyFormat, trimmed, err)
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: failed reading public key file: %v", ErrInvalidKeyFormat, err)
	}
	if len(raw) > maxKeyFileBytes {
		return nil, fmt.Errorf("%w: public key file exceeds %d bytes", ErrInvalidKeyFormat, maxKeyFileBytes)
	}

	content := strings.TrimSpace(string(raw))
	if len(content) == ed25519.PublicKeySize*2 {
		if b, err := hex.DecodeString(content); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}

	if block, _ := pem.Decode(raw); block != nil {
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid PKIX PEM public key: %v", ErrInvalidKeyFormat, err)
		}
		edPub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: PEM public key is not Ed25519", ErrInvalidKeyFormat)
		}
		return edPub, nil
	}

	return nil, fmt.Errorf("%w: expected 32-byte hex Ed25519 public key or PKIX PEM", ErrInvalidKeyFormat)
}

func defaultSignedOutputPath(inPath string) string {
	lower := strings.ToLower(inPath)
	switch {
	case strings.HasSuffix(lower, ".mentor.json"):
		return inPath[:len(inPath)-len(".mentor.json")] + ".capsule"
	case strings.HasSuffix(lower, ".json"):
		return inPath[:len(inPath)-len(".json")] + ".capsule"
	case strings.HasSuffix(lower, ".capsule"):
		return inPath[:len(inPath)-len(".capsule")] + ".signed.capsule"
	default:
		return inPath + ".capsule"
	}
}

// SignCapsuleFile validates (cognitive firewall + secret quarantine), computes canonical Merkle root,
// signs with the supplied Ed25519 private key, and emits either a `.capsule` (tar.gz) archive or
// signed `.json` manifest (if outPath ends with `.json`). Supports both Mentor (bonjoski-mentor-v1)
// and Requirements (bonjoski-requirements-v1) manifests.
func SignCapsuleFile(inPath, keySpec, outPath string) (*SignedCapsuleResult, error) {
	if strings.TrimSpace(inPath) == "" {
		return nil, fmt.Errorf("input manifest path is required")
	}
	privKey, err := LoadEd25519PrivateKey(keySpec)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(outPath) == "" {
		outPath = defaultSignedOutputPath(inPath)
	}
	if err := checkNoSymlinkPath(outPath); err != nil {
		return nil, err
	}

	asJSON := strings.HasSuffix(strings.ToLower(outPath), ".json")
	format := "capsule"
	if asJSON {
		format = "json"
	}

	schema := DetectCapsuleSchema(inPath)
	if schema == RequirementsSchemaVersion {
		m, err := ReadRequirementsCapsuleFile(inPath)
		if err != nil {
			return nil, err
		}
		if asJSON {
			if err := ExportRequirementsCapsuleJSON(m, outPath, privKey); err != nil {
				return nil, err
			}
		} else {
			if err := ExportRequirementsCapsule(m, outPath, privKey); err != nil {
				return nil, err
			}
		}
		return &SignedCapsuleResult{
			SchemaVersion: m.SchemaVersion,
			Name:          m.Name,
			Version:       m.Version,
			ItemCount:     len(m.Criteria),
			MerkleRoot:    m.MerkleRoot,
			AuthorityTier: m.AuthorityTier,
			Provenance:    ProvenanceVerifiedSigned,
			PublicKeyHex:  m.PublicKey,
			OutputPath:    outPath,
			Format:        format,
		}, nil
	}

	m, err := ReadMentorCapsuleFile(inPath)
	if err != nil {
		return nil, err
	}
	if asJSON {
		if err := ExportMentorCapsuleJSON(m, outPath, privKey); err != nil {
			return nil, err
		}
	} else {
		if err := ExportMentorCapsule(m, outPath, privKey); err != nil {
			return nil, err
		}
	}
	return &SignedCapsuleResult{
		SchemaVersion: m.SchemaVersion,
		Name:          m.Name,
		Version:       m.Version,
		ItemCount:     len(m.Cards),
		MerkleRoot:    m.MerkleRoot,
		AuthorityTier: m.AuthorityTier,
		Provenance:    ProvenanceVerifiedSigned,
		PublicKeyHex:  m.PublicKey,
		OutputPath:    outPath,
		Format:        format,
	}, nil
}

// PackCapsuleFile packages a Mentor or Requirements manifest into a verifiable `.capsule` (tar.gz) archive.
// If keySpec is provided, the manifest is freshly signed with Ed25519. If keySpec is omitted, an existing
// valid Ed25519 signature is verified and preserved (or unsigned packing requires allowUnsigned=true).
func PackCapsuleFile(inPath, keySpec, outPath string, allowUnsigned bool) (*SignedCapsuleResult, error) {
	if strings.TrimSpace(inPath) == "" {
		return nil, fmt.Errorf("input manifest path is required")
	}
	if strings.TrimSpace(outPath) == "" {
		outPath = defaultSignedOutputPath(inPath)
	}
	if strings.TrimSpace(keySpec) != "" {
		return SignCapsuleFile(inPath, keySpec, outPath)
	}
	if err := checkNoSymlinkPath(outPath); err != nil {
		return nil, err
	}

	schema := DetectCapsuleSchema(inPath)
	if schema == RequirementsSchemaVersion {
		m, err := ReadRequirementsCapsuleFile(inPath)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(m.MerkleRoot) == "" && allowUnsigned {
			m.MerkleRoot = ComputeRequirementsMerkleRoot(m.Criteria)
		}
		prov, err := VerifyRequirementsManifest(m, MentorImportOptions{AllowUnsigned: allowUnsigned})
		if err != nil {
			return nil, err
		}
		if err := ExportRequirementsCapsule(m, outPath, nil); err != nil {
			return nil, err
		}
		return &SignedCapsuleResult{
			SchemaVersion: m.SchemaVersion,
			Name:          m.Name,
			Version:       m.Version,
			ItemCount:     len(m.Criteria),
			MerkleRoot:    m.MerkleRoot,
			AuthorityTier: m.AuthorityTier,
			Provenance:    prov,
			PublicKeyHex:  m.PublicKey,
			OutputPath:    outPath,
			Format:        "capsule",
		}, nil
	}

	m, err := ReadMentorCapsuleFile(inPath)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(m.MerkleRoot) == "" && allowUnsigned {
		m.MerkleRoot = ComputeMerkleRoot(m.Cards)
	}
	prov, err := VerifyMentorManifest(m, MentorImportOptions{AllowUnsigned: allowUnsigned})
	if err != nil {
		return nil, err
	}
	if err := ExportMentorCapsule(m, outPath, nil); err != nil {
		return nil, err
	}
	return &SignedCapsuleResult{
		SchemaVersion: m.SchemaVersion,
		Name:          m.Name,
		Version:       m.Version,
		ItemCount:     len(m.Cards),
		MerkleRoot:    m.MerkleRoot,
		AuthorityTier: m.AuthorityTier,
		Provenance:    prov,
		PublicKeyHex:  m.PublicKey,
		OutputPath:    outPath,
		Format:        "capsule",
	}, nil
}

// VerifyCapsuleFile auto-detects Mentor or Requirements schema (in JSON or .capsule tar.gz form)
// and runs the full Two-Gate Import Quarantine (Merkle + Ed25519 + cognitive firewall + secret scan).
func VerifyCapsuleFile(path string, opts MentorImportOptions) (*VerifiedCapsuleResult, error) {
	if DetectCapsuleSchema(path) == RequirementsSchemaVersion {
		m, err := ReadRequirementsCapsuleFile(path)
		if err != nil {
			return nil, err
		}
		prov, err := VerifyRequirementsManifest(m, opts)
		if err != nil {
			return nil, err
		}
		return &VerifiedCapsuleResult{
			SchemaVersion: m.SchemaVersion,
			Name:          m.Name,
			Version:       m.Version,
			ItemCount:     len(m.Criteria),
			MerkleRoot:    m.MerkleRoot,
			AuthorityTier: TierMentorCapsule,
			Provenance:    prov,
		}, nil
	}

	m, err := ReadMentorCapsuleFile(path)
	if err != nil {
		return nil, err
	}
	prov, err := VerifyMentorManifest(m, opts)
	if err != nil {
		return nil, err
	}
	return &VerifiedCapsuleResult{
		SchemaVersion: m.SchemaVersion,
		Name:          m.Name,
		Version:       m.Version,
		ItemCount:     len(m.Cards),
		MerkleRoot:    m.MerkleRoot,
		AuthorityTier: TierMentorCapsule,
		Provenance:    prov,
	}, nil
}
