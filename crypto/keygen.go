package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
)

const maxRSAKeyLengthBits = 4096

var supportedECCurves = map[string]elliptic.Curve{
	"P-256": elliptic.P256(),
	"P-384": elliptic.P384(),
	"P-521": elliptic.P521(),
}

func GetMaxRSAKeyLengthBits() int {
	return maxRSAKeyLengthBits
}

func GenerateRSAKey(bitLength int) (rsaKey *rsa.PrivateKey, err error) {
	// dont try and generate too large of a key ;)
	if bitLength > maxRSAKeyLengthBits {
		err = fmt.Errorf("specified RSA key size is too large. Please decrease to a max of 4k")
		return
	}
	rsaKey, err = rsa.GenerateKey(rand.Reader, bitLength)
	return
}

func GetSupportedECCurves() map[string]elliptic.Curve {
	return supportedECCurves
}

func GenerateECKey(curve string) (ecKey *ecdsa.PrivateKey, err error) {
	if c, isSupported := supportedECCurves[strings.ToUpper(curve)]; isSupported {
		ecKey, err = ecdsa.GenerateKey(c, rand.Reader)
	} else {
		err = fmt.Errorf("invalid curve specified: %s", curve)
	}
	return
}
