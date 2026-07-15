package message

import "testing"

func TestDisposition_Constants(t *testing.T) {
	if DispositionInline != "inline" {
		t.Errorf("DispositionInline = %q, want %q", DispositionInline, "inline")
	}
	if DispositionAttachment != "attachment" {
		t.Errorf("DispositionAttachment = %q, want %q", DispositionAttachment, "attachment")
	}
}
