package message

import "testing"

func TestLimits_Normalized(t *testing.T) {
	tests := []struct {
		name string
		in   Limits
		want Limits
	}{
		{
			name: "all zero falls back to defaults",
			in:   Limits{},
			want: DefaultLimits(),
		},
		{
			name: "partial override keeps the rest at defaults",
			in:   Limits{MaxDepth: 3},
			want: Limits{
				MaxDepth:     3,
				MaxParts:     DefaultLimits().MaxParts,
				MaxHeaders:   DefaultLimits().MaxHeaders,
				MaxPartSize:  DefaultLimits().MaxPartSize,
				MaxTotalSize: DefaultLimits().MaxTotalSize,
			},
		},
		{
			name: "negative values are treated as unset",
			in:   Limits{MaxDepth: -1, MaxParts: -5},
			want: Limits{
				MaxDepth:     DefaultLimits().MaxDepth,
				MaxParts:     DefaultLimits().MaxParts,
				MaxHeaders:   DefaultLimits().MaxHeaders,
				MaxPartSize:  DefaultLimits().MaxPartSize,
				MaxTotalSize: DefaultLimits().MaxTotalSize,
			},
		},
		{
			name: "fully specified is unchanged",
			in: Limits{
				MaxDepth:     1,
				MaxParts:     2,
				MaxHeaders:   3,
				MaxPartSize:  4,
				MaxTotalSize: 5,
			},
			want: Limits{
				MaxDepth:     1,
				MaxParts:     2,
				MaxHeaders:   3,
				MaxPartSize:  4,
				MaxTotalSize: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.normalized()
			if got != tt.want {
				t.Errorf("normalized() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDefaultLimits_AreAllPositive(t *testing.T) {
	d := DefaultLimits()
	if d.MaxDepth <= 0 {
		t.Error("MaxDepth must be positive")
	}
	if d.MaxParts <= 0 {
		t.Error("MaxParts must be positive")
	}
	if d.MaxHeaders <= 0 {
		t.Error("MaxHeaders must be positive")
	}
	if d.MaxPartSize <= 0 {
		t.Error("MaxPartSize must be positive")
	}
	if d.MaxTotalSize <= 0 {
		t.Error("MaxTotalSize must be positive")
	}
}
