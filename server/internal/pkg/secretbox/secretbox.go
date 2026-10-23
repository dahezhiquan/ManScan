package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// Box encrypts and decrypts sensitive values using AES-GCM.
type Box struct {
	gcm cipher.AEAD
}

// New creates an AES-GCM box. The supplied secret is deterministically
// expanded to a 256-bit key so configuration can use a readable secret.
func New(secret string) (*Box, error) {
	if len(strings.TrimSpace(secret)) < 32 {
		return nil, fmt.Errorf("加密密钥必须至少为 32 个字节")
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("创建加密器失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建加密模式失败: %w", err)
	}
	return &Box{gcm: gcm}, nil
}

// Encrypt returns a base64 encoded AES-GCM ciphertext.
func (b *Box) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成加密随机数失败: %w", err)
	}
	ciphertext := b.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decodes and decrypts a base64 encoded AES-GCM ciphertext.
func (b *Box) Decrypt(encoded string) (string, error) {
	ciphertext, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("解码密文失败: %w", err)
	}
	nonceSize := b.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("密文长度不合法")
	}
	plaintext, err := b.gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("解密失败: %w", err)
	}
	return string(plaintext), nil
}
