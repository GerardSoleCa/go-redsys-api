package redsys

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test3DESEncryptionAndDecryption(t *testing.T) {
	const KEY = "Mk9m98IfEblmPfrpsawt7BmxObt98Jev"
	const DS_MERCHANT_ORDER = "1"
	const ENCRYPTED_TEXT = "Lr6bLJYWKrk="

	redsys := Redsys{}

	assert.Equal(t, redsys.encrypt3DES(DS_MERCHANT_ORDER, KEY), ENCRYPTED_TEXT, "Encryption result should be qual to " + ENCRYPTED_TEXT)

	assert.Equal(t, redsys.decrypt3DES(ENCRYPTED_TEXT, KEY), DS_MERCHANT_ORDER, "Decryption result should be qual to " + DS_MERCHANT_ORDER)

}

func TestSHA256Algorithm(t *testing.T) {
	const PARAMS = "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4ODEiLCJEU19NRVJDSEFOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5TQUNUSU9OVFlQRSI6IjAiLCJEU19NRVJDSEFOVF9URVJNSU5BTCI6Ijg3MSIsIkRTX01FUkNIQU5UX01FUkNIQU5UVVJMIjoiIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiIiLCJEU19NRVJDSEFOVF9VUkxLTyI6IiJ9"
	const SIGNATURE = "3TEI5WyvHf1D/whByt1ENgFH/HPIP9UFuB6LkCYgj+E="
	const ENCRYPTED_KEY = "Lr6bLJYWKrk="


	redsys := Redsys{}
	assert.Equal(t, redsys.mac256(PARAMS, ENCRYPTED_KEY), SIGNATURE, "SHA256 result should be qual to " + SIGNATURE)
}

funct