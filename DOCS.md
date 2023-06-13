# minica-p11 docs

PKCS11 supported minica. Use at own risk. Originial [README](./MINICA_README.md). Tested with softhsm2, Debian 11.

Init softhsm test token

```sh
softhsm2-util --init-token --free --label test --so-pin "1234" --pin "1234"
```

List slots

```sh
pkcs11-tool -L --module /usr/lib/softhsm/libsofthsm2.so
```

Create test keypair

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login  --pin 1234 --keypairgen --label 'testkey' --id '2929' --key-type rsa:2048
```

List publickey objects

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
--login --login-type user --pin 1234 --slot <slot-id> \
--list-objects --type pubkey
```

Read object

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot $SLOT --read-object --type pubkey --id $ID
```


sources

- https://xn--verschlsselt-jlb.it/export-a-rsa-ecc-public-key-with-opensc-pkcs11-tool/