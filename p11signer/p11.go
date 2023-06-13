package p11signer

import (
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

// TODO fix "handleError"

var modulePath string = "/usr/lib/softhsm/libsofthsm2.so"
var tokenPin string = "1234"
var p11 *pkcs11.Ctx
var session pkcs11.SessionHandle

func init() {
	fmt.Println("initing p11 module")
	p11 = pkcs11.New(modulePath)
	err := p11.Initialize()
	if err != nil {
		panic(err)
	}

	slots, err := p11.GetSlotList(true)
	handleFatal(err)
	slotId := uint(slots[0])
	session, err = p11.OpenSession(slotId, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	handleFatal(err)
	err = p11.Login(session, pkcs11.CKU_USER, tokenPin)
	handleFatal(err)
}

func Finalize() {
	defer p11.CloseSession(session)
	defer p11.Logout(session)
	defer p11.Destroy()
	defer p11.Finalize()
}

func getPublicKey(label string) rsa.PublicKey {
	class := pkcs11.CKO_PUBLIC_KEY
	findTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}
	err := p11.FindObjectsInit(session, findTemplate)
	handleFatal(err)
	oh, _, err := p11.FindObjects(session, 1)
	handleFatal(err)
	err = p11.FindObjectsFinal(session)
	handleFatal(err)
	objectAttrs, err := p11.GetAttributeValue(session, oh[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	handleFatal(err)

	// ! not sure about byte serialisations
	var pe int
	var mod *big.Int
	for _, a := range objectAttrs {
		switch a.Type {
		case pkcs11.CKA_PUBLIC_EXPONENT:
			pe = int(new(big.Int).SetBytes(a.Value).Int64())
		case pkcs11.CKA_MODULUS:
			mod = new(big.Int).SetBytes(a.Value)
		}
	}
	pubkey := rsa.PublicKey{N: mod, E: pe}
	return pubkey
}

func sign(label string, message []byte) (sig []byte) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}
	err := p11.FindObjectsInit(session, template)
	handleFatal(err)
	ohs, _, err := p11.FindObjects(session, 1)
	handleFatal(err)
	// fmt.Printf("ohs: %+v\n", ohs)
	// fmt.Printf("ohsLenght: %+v\n", len(ohs))
	handleFatal(err)
	err = p11.FindObjectsFinal(session)
	handleFatal(err)
	err = p11.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, ohs[0])
	handleFatal(err)
	signature, err := p11.Sign(session, message)
	fmt.Printf("signature: %x\n", signature)
	handleFatal(err)
	return signature
}

func handleFatal(err error) {
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}
