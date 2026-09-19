module fedmes/crypto

go 1.25.0

require (
	fedmes/security2 v0.0.0
	github.com/bytemare/opaque v0.18.0
	golang.org/x/mobile v0.0.0-20260520154334-0e4426e1883d
	maunium.net/go/mautrix v0.28.0
)

tool golang.org/x/mobile/cmd/gobind

replace github.com/bytemare/ksf => ./third_party/ksf

replace fedmes/security2 => ../security2
