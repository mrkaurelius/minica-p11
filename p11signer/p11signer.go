package p11signer

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
)

// How to init signer?
// P11Singer represent key pair not all pkcs11 stuff so pcs11 stuff should managed separately

type P11Signer struct {
	crypto.Signer

	label string
}

func (ps P11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (s []byte, err error) {
	fmt.Println("omg siging something")
	// digest is not really diges!
	return signP11(ps.label, digest)
}

// Although this type is an empty interface for backwards compatibility reasons, all public key types in the standard
// library implement the following interface
//
//	interface{
//	    Equal(x crypto.PublicKey) bool
//	}
func (ps P11Signer) Public() (p crypto.PublicKey) {
	p, err := ps.PublicKey()
	if err != nil {
		fmt.Printf("error: %s\n", err) // ??? Omit error
	}
	fmt.Printf("p:%+v\n", p)
	return p
}

func (ps P11Signer) PublicKey() (p rsa.PublicKey, err error) {
	return getPublicKey(ps.label)
}

// init p11signer and return, privLabel: privatekey object label, publabel: public key object label
func New(label string) P11Signer {
	return P11Signer{label: label}
}
