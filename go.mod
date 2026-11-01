module github.com/metacubex/sing-vmess

go 1.20

require (
	github.com/gofrs/uuid/v5 v5.3.2
	github.com/metacubex/sing v0.5.7
	golang.org/x/crypto v0.31.0
)

require golang.org/x/sys v0.28.0 // indirect

replace github.com/metacubex/sing => github.com/Herta-Network/sing v0.0.0-20261101103341-a402b0b490ba
