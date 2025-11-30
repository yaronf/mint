module github.com/bifurcation/mint/attestation

go 1.23.0

toolchain go1.24.1

require (
	github.com/bifurcation/mint v0.0.0
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/veraison/cmw v0.2.0
)

require (
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a // indirect
)

replace github.com/bifurcation/mint => ../
