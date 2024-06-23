package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func MarshalString(dataset string, secretKey []byte) (string, error) {
	if len(dataset) == 0 {
		return "", fmt.Errorf("dataset is empty")
	}
	if len(secretKey) == 0 {
		return dataset, nil
	}

	src, err := Marshal([]byte(dataset), secretKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(src), nil
}

func Marshal(dataset []byte, secretKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(dataset))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], dataset)

	return ciphertext, nil
}

func UnmarshalString(dataset string, secretKey []byte) (string, error) {
	if len(dataset) == 0 {
		return "", fmt.Errorf("dataset is empty")
	}
	if len(secretKey) == 0 {
		return dataset, nil
	}

	src, err := base64.StdEncoding.DecodeString(dataset)
	if err != nil {
		return "", err
	}

	desc, err := Unmarshal(src, secretKey)
	if err != nil {
		return "", err
	}
	return string(desc), nil
}

func Unmarshal(dataset []byte, secretKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	iv := dataset[:aes.BlockSize]
	ciphertext := dataset[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}
