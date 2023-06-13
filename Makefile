all:
	go build -o minica-p11 ./cmd/main.go

test:
	go test ./p11signer -v -count=1