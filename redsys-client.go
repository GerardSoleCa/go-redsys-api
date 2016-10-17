package redsys

import (
	"encoding/base64"
	"log"
	"crypto/des"
	"crypto/cipher"
	"bytes"
)

var IV = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

type Redsys struct {

}

func (r *Redsys) encrypt3DES(str string, key string) string {

	block := getCipher(key)
	cbc := cipher.NewCBCEncrypter(block, IV)

	decrypted := []byte(str)
	decryptedPadded, _ := zeroPad(decrypted, block.BlockSize())
	cbc.CryptBlocks(decryptedPadded, decryptedPadded)

	return base64.StdEncoding.EncodeToString(decryptedPadded)
}

func (r *Redsys) decrypt3DES(str string, key string) string {

	block := getCipher(key)
	cbc := cipher.NewCBCDecrypter(block, IV)

	encrypted, _ := base64.StdEncoding.DecodeString(str)
	cbc.CryptBlocks(encrypted, encrypted)

	unpaddedResult, _ := zeroUnpad(encrypted, block.BlockSize())

	return string(unpaddedResult)
}

func getCipher(key string) cipher.Block {
	secretKey, err := base64.StdEncoding.DecodeString(key)

	if err != nil {
		log.Panic("Error decoding key", err)
	}

	crypto, err := des.NewTripleDESCipher(secretKey)
	if err != nil {
		log.Panic("Error generating cipher", err)
	}
	return crypto
}

// zeroPad function to terminate blocksize in zeros
func zeroPad(data []byte, blocklen int) ([]byte, error) {
	padlen := (blocklen - (len(data) % blocklen)) % blocklen
	pad := bytes.Repeat([]byte{0x00}, padlen)

	return append(data, pad...), nil
}

// zeroUnpad function to remove trailing zeros
func zeroUnpad(data []byte, blocklen int) ([]byte, error) {
	lastIndex := len(data);
	for (lastIndex >= 0 && lastIndex > len(data) - blocklen - 1) {
		lastIndex--;
		if (data[lastIndex] != 0) {
			break;
		}
	}
	return data[:lastIndex + 1], nil
}