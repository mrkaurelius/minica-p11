package p11hello

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

var modulePath string = "/usr/lib/softhsm/libsofthsm2.so"
var tokenPin string = "1234"
var p11 *pkcs11.Ctx

func init() {
	p11 = pkcs11.New(modulePath)
	err := p11.Initialize()
	if err != nil {
		panic(err)
	}

	defer p11.Destroy()
	defer p11.Finalize()
}

// TODO happy path'i calistir
func P11HappyPath() {
	// TODO check if softhsm installed

	info, err := p11.GetInfo()
	handleError(err)
	fmt.Printf("info %+v\n", info)

	slots, err := p11.GetSlotList(true)
	handleError(err)
	fmt.Printf("slots %+v\n", slots)
	for i, v := range slots {
		info, err := p11.GetSlotInfo(v)
		handleError(err)
		fmt.Printf("slot %d: %+v\n", i, info)
	}

	slotId := uint(slots[0])
	tokenInfo, err := p11.GetTokenInfo(slotId)
	handleError(err)
	fmt.Printf("tokenInfo: %+v\n", tokenInfo)

	session, err := p11.OpenSession(slotId, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	handleError(err)
	defer p11.CloseSession(session)

	err = p11.Login(session, pkcs11.CKU_USER, tokenPin)
	handleError(err)
	defer p11.Logout(session)

	p11.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256, nil)})
	message := []byte("this is a string")
	fmt.Printf("message: [%+x], [%s]\n", message, message)
	hash, err := p11.Digest(session, message)
	handleError(err)
	for _, d := range hash {
		fmt.Printf("%x", d)
	}
	fmt.Println()

	// CKO_PRIVATE_KEY or CKO_PUBLIC_KEY
	class := pkcs11.CKO_PRIVATE_KEY

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "test"),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}
	err = p11.FindObjectsInit(session, template)
	handleError(err)
	oh, _, err := p11.FindObjects(session, 1)
	handleError(err)
	fmt.Printf("objectHandle: %+v\n", oh)
	objectAttrs, err := p11.GetAttributeValue(session, oh[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	})
	handleError(err)
	err = p11.FindObjectsFinal(session)
	handleError(err)
	for i, a := range objectAttrs {
		fmt.Printf("attr %d, type %d, attr value %s\n", i, a.Type, a.Value)
	}

	message = []byte("merhaba yalan imza")
	err = p11.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, oh[0])
	handleError(err)
	signature, err := p11.Sign(session, message)
	handleError(err)
	fmt.Printf("signature: %x\n", signature)

}

func handleError(err error) {
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}
