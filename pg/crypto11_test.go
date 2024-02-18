package pg

// Notlar
// Dayilar context kullanmislar, bu durumda kullanmak gercekten mantikli.
// Context olayini anlamak icin iyi bir ornek olabilir

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/ThalesIgnite/crypto11"
)

const (
	softHsmPath = "/usr/lib/softhsm/libsofthsm2.so"
	tokenLabel  = "testtoken"
)

func TestCrypto11Happy(t *testing.T) {

	// Bu context'in nasil bir compositon'u var? neden boyle bir api tercih edilmis?
	ctx, err := crypto11.Configure(&crypto11.Config{Path: softHsmPath, TokenLabel: tokenLabel, Pin: tokenPin})
	if err != nil {
		t.Fatal(err)
	}

	// Take a look at crypto token's keys

	keys, err := ctx.FindAllKeyPairs()
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range keys {
		fmt.Printf("key: %+v\n", k.Public())

		// ?
		rp := k.Public().(*rsa.PublicKey)

		pPemB := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(rp),
		}

		pPemBytes := pem.EncodeToMemory(pPemB)

		fmt.Printf(string(pPemBytes))
	}

	// Sign something

}
