package p11signer

import (
	"crypto"
	"crypto/rsa"
	"io"
)

// How to init signer?
// P11Singer represent key pair not all pkcs11 stuff so pcs11 stuff should managed separately

type P11Signer struct {
	_     crypto.Signer
	label string
}

func (ps P11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// digest is not really diges!
	return sign(ps.label, digest), nil
}

// Although this type is an empty interface for backwards compatibility reasons, all public key types in the standard
// library implement the following interface
//
//	interface{
//	    Equal(x crypto.PublicKey) bool
//	}
func (ps P11Signer) Public() crypto.PublicKey {
	public := ps.PublicKey()
	return &public
}

func (ps P11Signer) PublicKey() rsa.PublicKey {
	pkey := getPublicKey(ps.label)
	return pkey
}

// init p11signer and return, privLabel: privatekey object label, publabel: public key object label
func New(label string) P11Signer {
	return P11Signer{label: label}
}
