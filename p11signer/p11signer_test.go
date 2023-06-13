package p11signer_test

import (
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/mrkaurelius/minica-p11/p11signer"
)

func TestP11Signer(t *testing.T) {
	p11 := p11signer.New("testkey")
	// p11.Sign(nil, []byte("merhabayalandunya"), nil)
	certb, err := p11signer.NewBasicCert(p11)
	if err != nil {
		panic(err)
	}

	fmt.Printf("cert %x\n", certb)
	println(string(pem.EncodeToMemory(&pem.Block{Bytes: certb, Type: "CERTIFICATE"})))
}
