package security

import (
	"errors"
	"strings"
	"testing"
)

func TestSanitizeMemory_RejectsStandaloneCredentials(t *testing.T) {
	// 1. Raw private key should fail closed
	rawPrivKey := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG
-----END EC PRIVATE KEY-----`
	_, err := SanitizeMemory(rawPrivKey)
	if !errors.Is(err, ErrSecretRejected) {
		t.Fatalf("expected ErrSecretRejected for raw private key, got: %v", err)
	}

	// 2. Standalone high-entropy raw secret token
	rawSecret := "dGhpcy1pcy1hLWhpZ2gtZW50cm9weS1zZWNyZXQta2V5LTEyMzQ1Njc4OTA="
	_, err = SanitizeMemory(rawSecret)
	if !errors.Is(err, ErrSecretRejected) {
		t.Fatalf("expected ErrSecretRejected for raw high-entropy token, got: %v", err)
	}
}

func TestSanitizeMemory_RedactsEmbeddedCredentials(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedSub string
		redactedMin int
	}{
		{
			name:        "OpenAI API Key",
			input:       "Failed model call using key sk-proj-1234567890abcdef1234567890abcdef in worker",
			expectedSub: "[REDACTED_OPENAI_KEY]",
			redactedMin: 1,
		},
		{
			name:        "Anthropic API Key",
			input:       "Configured Claude with sk-ant-api03-abcdef1234567890abcdef1234567890-abcdef",
			expectedSub: "[REDACTED_ANTHROPIC_KEY]",
			redactedMin: 1,
		},
		{
			name:        "AWS Access Key",
			input:       "Deployment failed for IAM user AKIAIOSFODNN7EXAMPLE",
			expectedSub: "[REDACTED_AWS_KEY]",
			redactedMin: 1,
		},
		{
			name:        "GitHub PAT",
			input:       "Pushed to origin with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
			expectedSub: "[REDACTED_GITHUB_TOKEN]",
			redactedMin: 1,
		},
		{
			name:        "PostgreSQL URI Password",
			input:       "Database URL is postgres://dbadmin:SuperSecretPassword123!@10.0.0.1:5432/proddb",
			expectedSub: "postgres://dbadmin:[REDACTED_PASSWORD]@10.0.0.1:5432/proddb",
			redactedMin: 1,
		},
		{
			name:        "Quoted API Key Assignment",
			input:       `export API_KEY="my-super-secret-production-token"`,
			expectedSub: `API_KEY="[REDACTED_CREDENTIAL]"`,
			redactedMin: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := SanitizeMemory(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.RedactedCount < tc.redactedMin {
				t.Errorf("expected at least %d redactions, got %d", tc.redactedMin, res.RedactedCount)
			}
			if !strings.Contains(res.SanitizedText, tc.expectedSub) {
				t.Errorf("expected output to contain %q, got: %q", tc.expectedSub, res.SanitizedText)
			}
		})
	}
}
