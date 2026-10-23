package secretbox_test

import (
	"encoding/base64"
	"testing"

	"ManScan/server/internal/pkg/secretbox"
)

func TestBoxEncryptDecrypt(t *testing.T) {
	box, err := secretbox.New("a sufficiently long API key encryption secret")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ciphertext, err := box.Encrypt("third-party-api-key")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if ciphertext == "third-party-api-key" || ciphertext == "" {
		t.Fatalf("ciphertext = %q, want non-plaintext value", ciphertext)
	}
	plaintext, err := box.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if plaintext != "third-party-api-key" {
		t.Fatalf("plaintext = %q, want original value", plaintext)
	}
	second, err := box.Encrypt(plaintext)
	if err != nil || second == ciphertext {
		t.Fatalf("Encrypt(same plaintext) must use a fresh nonce, error = %v", err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	for _, invalid := range []string{"", "not-base64!", base64.RawStdEncoding.EncodeToString(raw)} {
		if _, err := box.Decrypt(invalid); err == nil {
			t.Fatal("Decrypt() accepted malformed or tampered ciphertext")
		}
	}
	otherBox, err := secretbox.New("another sufficiently long encryption secret")
	if err != nil {
		t.Fatalf("New(other) error = %v", err)
	}
	if _, err := otherBox.Decrypt(ciphertext); err == nil {
		t.Fatal("Decrypt() with another key error = nil, want authentication failure")
	}
}

func TestBoxRejectsShortSecret(t *testing.T) {
	for _, secret := range []string{"", "short", "                                "} {
		if _, err := secretbox.New(secret); err == nil {
			t.Fatal("New() accepted an empty or short secret")
		}
	}
}
