package version

import (
	"regexp"
	"testing"
)

func TestVersionFollowsSemver(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
	if Version[0] != 'v' {
		t.Fatalf("Version %q must start with 'v'", Version)
	}
	semver := regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	rest := Version[1:]
	if !semver.MatchString(rest) {
		t.Fatalf("Version %q must follow semver after the v prefix (eg v1.2.3, v1.2.3-rc.1, v1.2.3+build.7)", Version)
	}
}
