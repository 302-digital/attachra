package version

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct {
		name    string
		version string
		commit  string
		date    string
		want    string
	}{
		{
			name:    "defaults",
			version: "dev",
			commit:  "none",
			date:    "unknown",
			want:    "attachra dev (commit none, built unknown)",
		},
		{
			name:    "release build",
			version: "v1.2.3",
			commit:  "abcdef0",
			date:    "2026-07-04T00:00:00Z",
			want:    "attachra v1.2.3 (commit abcdef0, built 2026-07-04T00:00:00Z)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origVersion, origCommit, origDate := Version, Commit, Date
			defer func() { Version, Commit, Date = origVersion, origCommit, origDate }()

			Version, Commit, Date = tt.version, tt.commit, tt.date

			got := String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if !strings.Contains(got, tt.version) {
				t.Errorf("String() = %q, want it to contain version %q", got, tt.version)
			}
		})
	}
}
