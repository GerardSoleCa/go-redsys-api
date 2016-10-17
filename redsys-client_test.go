package redsys

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const KEY = "Mk9m98IfEblmPfrpsawt7BmxObt98Jev"
const DS_MERCHANT_ORDER = "1"

func Test3DESEncryptionAndDecryption(t *testing.T) {
	encryptedText := "Lr6bLJYWKrk="
	redsys := Redsys{}

	assert.Equal(t, redsys.encrypt3DES(DS_MERCHANT_ORDER, KEY), encryptedText, "Encryption result should be qual to " + encryptedText)

	assert.Equal(t, redsys.decrypt3DES(encryptedText, KEY), DS_MERCHANT_ORDER, "Decryption result should be qual to " + DS_MERCHANT_ORDER)

}