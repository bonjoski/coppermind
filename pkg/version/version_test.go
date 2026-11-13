package version

import (
	"strings"
	"testing"
)

func TestVersion_Format(t *testing.T) {
	str := String()
	if !strings.Contains(str, Version) {
		t.Errorf("expected version string to contain %q, got %q", Version, str)
	}
}
