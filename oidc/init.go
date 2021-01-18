package oidc

// InitProvider will initialize this package. It is REQUIRED to be called
// first before this package can be of any use
func InitProvider() (err error) {
	// poll discovery URL first before initializing our private keys
	// since it's cheaper (on the CPU) to fail here (optimization FTW!)
	err = pollDiscovery()
	if err != nil {
		return
	}
	// no errors to catch here, since this function will already
	// fatally fail on any error
	initJwtSigningKey()
	return
}
