package crypto

import (
	"testing"
)

func TestKeyGenRSA(t *testing.T) {
	lengthsToTest := []int{1024, 2048, 4096}
	for _, size := range lengthsToTest {
		key, err := GenerateRSAKey(size)
		if err != nil || key == nil {
			t.Errorf("could not generate an RSA key of size %d: %v", size, err)
		}
		// key.Size() is in bytes. size is in bits
		if key.Size()*8 != size {
			t.Errorf("expected key size of %d but got %d", size, key.Size())
		}
	}

	// test too large of a length
	key, err := GenerateRSAKey(maxRSAKeyLengthBits + 1)
	if err == nil && key != nil {
		t.Errorf("expected not to be able to generate key that exeecds maxRSAKeyLengthBits")
	}
}

func TestKeyGenEC(t *testing.T) {
	for curveName, _ := range supportedECCurves {
		key, err := GenerateECKey(curveName)
		if err != nil || key == nil {
			t.Errorf("could not generate an EC key with curve %s: %v", curveName, err)
		}
	}

	// test invalid curve
	key, err := GenerateECKey("invalid")
	if err == nil && key != nil {
		t.Errorf("expected not to be able to generate an EC key with invalid curve")
	}
}
