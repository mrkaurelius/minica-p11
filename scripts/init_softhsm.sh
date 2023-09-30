#!/bin/bash

set -e

# init softhsm slot with label "test"

# look out permissions for softhsm installation
softhsm2-util --init-token --slot 0 --label testtoken --pin 1234 --so-pin 1234

# list slots and tokens
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -T

# generate key
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so  --slot-index 0 --login --login-type user \
    --keypairgen --id 29 --label testkey --key-type rsa:2048 --pin 1234