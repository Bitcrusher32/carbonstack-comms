package crypto

import "testing"

func TestMockCryptoProviderRoundTrip(t *testing.T) {
	provider := MockCryptoProvider{}

	plaintext := "hello from mock crypto"
	ciphertext := provider.Encrypt(plaintext)
	decrypted := provider.Decrypt(ciphertext)

	if decrypted != plaintext {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestMockCryptoProviderInvalidCiphertext(t *testing.T) {
	provider := MockCryptoProvider{}

	got := provider.Decrypt("not base64 !!!")
	want := "[invalid stub ciphertext]"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestMockCryptoConstants(t *testing.T) {
	if ContentTypeTextStub != "carbonstack.message.text.stub.v0" {
		t.Fatalf("unexpected content type: %s", ContentTypeTextStub)
	}

	if ProtocolVersionStub != "stub-v0" {
		t.Fatalf("unexpected protocol version: %s", ProtocolVersionStub)
	}
}
