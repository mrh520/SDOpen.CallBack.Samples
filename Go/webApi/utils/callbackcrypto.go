package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CallbackCrypto handles encryption and decryption for callback messages
type CallbackCrypto struct {
	aesKey   []byte
	clientID string
}

const randomLength = 16

// NewCallbackCrypto initializes a new CallbackCrypto instance
func NewCallbackCrypto(encodingAesKey, clientID string) (*CallbackCrypto, error) {
	if encodingAesKey == "" {
		return nil, errors.New("encryption key cannot be empty")
	}
	aesKey, err := base64.StdEncoding.DecodeString(encodingAesKey)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encodingAesKey: %v", err)
	}
	return &CallbackCrypto{
		aesKey:   aesKey,
		clientID: clientID,
	}, nil
}

// GetEncryptedMap encrypts a plaintext message and returns a map with encrypted data
func (c *CallbackCrypto) GetEncryptedMap(plaintext string, timestamp int64) (map[string]string, error) {
	if plaintext == "" {
		return nil, errors.New("plaintext cannot be empty")
	}

	nonce := getRandomStr(randomLength)
	encrypt, err := c.encrypt(nonce, plaintext)
	if err != nil {
		return nil, err
	}
	signature := c.getSignature(strconv.FormatInt(timestamp, 10), nonce, encrypt)

	return map[string]string{
		"signature": signature,
		"encrypt":   encrypt,
		"timestamp": strconv.FormatInt(timestamp, 10),
		"nonce":     nonce,
	}, nil
}

// GetDecryptMsg decrypts an encrypted message after verifying the signature
func (c *CallbackCrypto) GetDecryptMsg(msgSignature, timestamp, nonce, encryptMsg string) (string, error) {
	signature := c.getSignature(timestamp, nonce, encryptMsg)
	if signature != msgSignature {
		return "", errors.New("signature mismatch")
	}
	return c.decrypt(encryptMsg)
}

// encrypt encrypts a plaintext message
func (c *CallbackCrypto) encrypt(nonce, plaintext string) (string, error) {
	randomBytes := []byte(nonce)
	plainTextBytes := []byte(plaintext)
	lengthBytes := int2Bytes(len(plainTextBytes))
	clientIDBytes := []byte(c.clientID)

	data := bytes.Join([][]byte{randomBytes, lengthBytes, plainTextBytes, clientIDBytes}, nil)
	paddedData, err := pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return "", err
	}
	iv := c.aesKey[:16]
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts an encrypted message
func (c *CallbackCrypto) decrypt(text string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", fmt.Errorf("invalid base64 ciphertext: %v", err)
	}

	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return "", err
	}
	iv := c.aesKey[:16]
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", err
	}

	if len(unpadded) < randomLength+4 {
		return "", errors.New("decrypted data too short")
	}

	plainTextLength := bytes2Int(unpadded[randomLength : randomLength+4])
	if len(unpadded) < randomLength+4+plainTextLength {
		return "", errors.New("invalid plaintext length")
	}

	plaintextData := unpadded[randomLength+4 : randomLength+4+plainTextLength]
	msgClientID := string(unpadded[randomLength+4+plainTextLength:])
	if msgClientID != c.clientID {
		return "", errors.New("clientID mismatch in decrypted message")
	}

	return string(plaintextData), nil
}

// getSignature generates a SHA1 signature
func (c *CallbackCrypto) getSignature(timestamp, nonce, encrypt string) string {
	array := []string{c.clientID, timestamp, nonce, encrypt}
	sort.Strings(array)
	data := strings.Join(array, "")
	hash := sha1.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// Utility functions

func getRandomStr(count int) string {
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	sb := strings.Builder{}
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < count; i++ {
		sb.WriteByte(chars[rand.Intn(len(chars))])
	}
	return sb.String()
}

func int2Bytes(n int) []byte {
	return []byte{
		byte(n >> 24 & 0xFF),
		byte(n >> 16 & 0xFF),
		byte(n >> 8 & 0xFF),
		byte(n & 0xFF),
	}
}

func bytes2Int(b []byte) int {
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}

func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...), nil
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	padding := int(data[len(data)-1])
	if padding < 1 || padding > len(data) {
		return nil, errors.New("invalid padding")
	}
	return data[:len(data)-padding], nil
}
