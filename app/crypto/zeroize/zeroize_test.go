package zeroize

import "testing"

func TestBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Bytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
}

func TestBytesEmpty(t *testing.T) {
	Bytes(nil)
	Bytes([]byte{})
}

func TestMulti(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{4, 5, 6}
	Multi(a, nil, b)
	for _, x := range append(a, b...) {
		if x != 0 {
			t.Fatalf("not zeroed: %v %v", a, b)
		}
	}
}
