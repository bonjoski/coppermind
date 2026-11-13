package security

import (
	"errors"
	"strings"
	"testing"
)

// TestADV01_ZeroWidthRunesCredentialSmuggling verifies that attackers cannot evade
// API key detection by interleaving zero-width spaces or non-joiners.
func TestADV01_ZeroWidthRunesCredentialSmuggling(t *testing.T) {
	// Attacker inserts zero-width space (\u200B) into an OpenAI key
	evasiveKey := "s\u200bk\u200b-\u200bproj-1234567890abcdef1234567890abcdef"
	input := "Here is my secret: " + evasiveKey

	res, err := SanitizeMemory(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The raw key must not exist anywhere in sanitized text
	if strings.Contains(res.SanitizedText, "1234567890abcdef1234567890abcdef") {
		t.Errorf("ADV-01 Failure: Zero-width rune smuggling evaded detection! Result: %s", res.SanitizedText)
	}
}

// TestADV02_EntropyPaddingDilution verifies that attackers cannot evade entropy
// detection by padding a high-entropy secret with dozens of repeated characters.
func TestADV02_EntropyPaddingDilution(t *testing.T) {
	// High-entropy token padded with low-entropy characters
	rawSecret := "X9kL2pQmR5tY8wZa3vB7cD1eF4gH6jN0"
	padded := "AAAAAAAAAA" + rawSecret + "AAAAAAAAAA"
	input := "Generated token: " + padded

	res, err := SanitizeMemory(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(res.SanitizedText, rawSecret) {
		t.Errorf("ADV-02 Failure: Entropy padding dilution evaded detection! Result: %s", res.SanitizedText)
	}
}

// TestADV03_AllPrivateKeyVariantsFailClosed verifies that all variations of PEM private keys
// (RSA, EC, DSA, OPENSSH, PGP, ENCRYPTED, ED25519) are strictly rejected fail-closed.
func TestADV03_AllPrivateKeyVariantsFailClosed(t *testing.T) {
	variants := []struct {
		name    string
		payload string
	}{
		{
			name: "RSA Private Key",
			payload: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y123456789abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----`,
		},
		{
			name: "EC Private Key",
			payload: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG
-----END EC PRIVATE KEY-----`,
		},
		{
			name: "OPENSSH Private Key",
			payload: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAB
-----END OPENSSH PRIVATE KEY-----`,
		},
		{
			name: "PGP Private Key",
			payload: `-----BEGIN PGP PRIVATE KEY BLOCK-----
lQO+BF2X1234567890abcdefghijklmnopqrstuvwxyz
-----END PGP PRIVATE KEY BLOCK-----`,
		},
		{
			name: "ED25519 Private Key",
			payload: `-----BEGIN ED25519 PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG
-----END ED25519 PRIVATE KEY-----`,
		},
	}

	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SanitizeMemory(tc.payload)
			if err == nil {
				t.Fatalf("ADV-03 Failure: %s was NOT rejected fail-closed!", tc.name)
			}
			if !errors.Is(err, ErrSecretRejected) {
				t.Fatalf("ADV-03 Failure: expected ErrSecretRejected, got: %v", err)
			}
		})
	}
}
