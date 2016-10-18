package redsys

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"log"
)

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
	lastIndex := len(data)
	for lastIndex >= 0 && lastIndex > len(data)-blocklen-1 {
		lastIndex--
		if data[lastIndex] != 0 {
			break
		}
	}
	return data[:lastIndex+1], nil
}
