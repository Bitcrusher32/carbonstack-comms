package crypto

import "encoding/base64"

const (
	ContentTypeTextStub = "carbonstack.message.text.stub.v0"
	ProtocolVersionStub = "stub-v0"
)

type MockCryptoProvider struct{}

func (MockCryptoProvider) Encrypt(plaintext string) string {
	return base64.StdEncoding.EncodeToString([]byte(plaintext))
}

func (MockCryptoProvider) Decrypt(ciphertextB64 string) string {
	decoded, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "[invalid stub ciphertext]"
	}
	return string(decoded)
}
