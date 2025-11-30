module github.com/bifurcation/mint

go 1.23.0

toolchain go1.24.1

require (
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e
)

require golang.org/x/text v0.3.6 // indirect

replace github.com/bifurcation/mint/attestation => ./attestation
