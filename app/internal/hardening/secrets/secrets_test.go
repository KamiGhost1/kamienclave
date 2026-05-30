package secrets

import "testing"

func TestRegisterAndWipeAll(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{9, 9}
	Register(a)
	Register(b)
	Register(nil) // ignored
	Register([]byte{})

	if Count() != 2 {
		t.Fatalf("Count = %d, want 2", Count())
	}

	WipeAll()

	for i, v := range a {
		if v != 0 {
			t.Fatalf("a[%d] = %d, not wiped", i, v)
		}
	}
	for i, v := range b {
		if v != 0 {
			t.Fatalf("b[%d] = %d, not wiped", i, v)
		}
	}
	if Count() != 0 {
		t.Fatalf("Count after WipeAll = %d, want 0", Count())
	}

	// Second WipeAll is a no-op, must not panic.
	WipeAll()
}
