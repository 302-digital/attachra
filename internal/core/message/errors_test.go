package message

import "testing"

func TestLimitError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *LimitError
		want string
	}{
		{
			name: "with part path",
			err:  newLimitError(LimitDepth, "0.1.2", 10),
			want: `message: depth limit exceeded at part "0.1.2" (limit=10)`,
		},
		{
			name: "without part path (message-wide limit)",
			err:  newLimitError(LimitTotalSize, "", 1024),
			want: "message: total_size limit exceeded (limit=1024)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLimitError_ImplementsError(t *testing.T) {
	var err error = newLimitError(LimitParts, "0", 5)
	if err.Error() == "" {
		t.Error("Error() returned empty string")
	}
}
