package samlsp

import (
	"io"

	"github.com/adalundhe/saml-gin"
)

func randomBytes(n int) []byte {
	rv := make([]byte, n)

	if _, err := io.ReadFull(saml.RandReader, rv); err != nil {
		panic(err)
	}
	return rv
}
