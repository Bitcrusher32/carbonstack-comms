package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type ErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type DevInviteResponse struct {
	InviteID   string `json:"invite_id"`
	InviteCode string `json:"invite_code"`
	CreatedAt  string `json:"created_at"`
}

type ClaimInviteResponse struct {
	AccountID string `json:"account_id"`
	CreatedAt string `json:"created_at"`
}

type RegisterDeviceResponse struct {
	DeviceID  string `json:"device_id"`
	AccountID string `json:"account_id"`
	CreatedAt string `json:"created_at"`
}

type DeviceRecord struct {
	DeviceID           string `json:"device_id"`
	DeviceLabel        string `json:"device_label"`
	PublicIdentityKey  string `json:"public_identity_key"`
	PublicPrekeyBundle string `json:"public_prekey_bundle"`
	CreatedAt          string `json:"created_at"`
}

type ListDevicesResponse struct {
	AccountID string         `json:"account_id"`
	Devices   []DeviceRecord `json:"devices"`
}

type SubmitEnvelopeResponse struct {
	EnvelopeID       string `json:"envelope_id"`
	DeliveryState    string `json:"delivery_state"`
	ServerReceivedAt string `json:"server_received_at"`
}

type EnvelopeRecord struct {
	EnvelopeID        string `json:"envelope_id"`
	SenderDeviceID    string `json:"sender_device_id"`
	RecipientDeviceID string `json:"recipient_device_id"`
	ContentType       string `json:"content_type"`
	ProtocolVersion   string `json:"protocol_version"`
	CiphertextB64     string `json:"ciphertext_b64"`
	ClientCreatedAt   string `json:"client_created_at"`
	ServerReceivedAt  string `json:"server_received_at"`
	DeliveryState     string `json:"delivery_state"`
}

type InboxResponse struct {
	DeviceID  string           `json:"device_id"`
	Envelopes []EnvelopeRecord `json:"envelopes"`
}

type AckEnvelopeResponse struct {
	EnvelopeID     string `json:"envelope_id"`
	DeliveryState  string `json:"delivery_state"`
	AcknowledgedAt string `json:"acknowledged_at"`
}

type CypherClient struct {
	ServerURL string
}

func New(serverURL string) CypherClient {
	return CypherClient{ServerURL: serverURL}
}

func (c CypherClient) CreateDevInvite(inviteCode string) (DevInviteResponse, error) {
	var resp DevInviteResponse
	req := map[string]string{"invite_code": inviteCode}
	err := postJSON(c.ServerURL+"/v0/dev/invites", req, &resp)
	return resp, err
}

func (c CypherClient) ClaimInvite(inviteCode string, displayName string) (ClaimInviteResponse, error) {
	var resp ClaimInviteResponse
	req := map[string]string{
		"invite_code":  inviteCode,
		"display_name": displayName,
	}
	err := postJSON(c.ServerURL+"/v0/invites/claim", req, &resp)
	return resp, err
}

func (c CypherClient) RegisterDevice(accountID string, label string, publicIdentityKey string, publicPrekeyBundle string) (RegisterDeviceResponse, error) {
	var resp RegisterDeviceResponse
	req := map[string]string{
		"account_id":           accountID,
		"device_label":         label,
		"public_identity_key":  publicIdentityKey,
		"public_prekey_bundle": publicPrekeyBundle,
	}
	err := postJSON(c.ServerURL+"/v0/devices/register", req, &resp)
	return resp, err
}

func (c CypherClient) ListDevices(accountID string) (ListDevicesResponse, error) {
	var resp ListDevicesResponse
	err := getJSON(c.ServerURL+"/v0/accounts/"+accountID+"/devices", &resp)
	return resp, err
}

func (c CypherClient) SubmitEnvelope(senderDeviceID string, recipientDeviceID string, contentType string, protocolVersion string, ciphertextB64 string, clientCreatedAt string) (SubmitEnvelopeResponse, error) {
	var resp SubmitEnvelopeResponse
	req := map[string]string{
		"sender_device_id":    senderDeviceID,
		"recipient_device_id": recipientDeviceID,
		"content_type":        contentType,
		"protocol_version":    protocolVersion,
		"ciphertext_b64":      ciphertextB64,
		"client_created_at":   clientCreatedAt,
	}
	err := postJSON(c.ServerURL+"/v0/envelopes", req, &resp)
	return resp, err
}

func (c CypherClient) Inbox(deviceID string) (InboxResponse, error) {
	var resp InboxResponse
	err := getJSON(c.ServerURL+"/v0/devices/"+deviceID+"/envelopes", &resp)
	return resp, err
}

func (c CypherClient) AckEnvelope(envelopeID string, recipientDeviceID string) (AckEnvelopeResponse, error) {
	var resp AckEnvelopeResponse
	req := map[string]string{
		"recipient_device_id": recipientDeviceID,
	}
	err := postJSON(c.ServerURL+"/v0/envelopes/"+envelopeID+"/ack", req, &resp)
	return resp, err
}

func postJSON(url string, req any, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpResp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	return decodeResponse(httpResp, out)
}

func getJSON(url string, out any) error {
	httpResp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	return decodeResponse(httpResp, out)
}

func decodeResponse(resp *http.Response, out any) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var er ErrorResponse
		if json.Unmarshal(body, &er) == nil && er.Error.Code != "" {
			return fmt.Errorf("%s: %s", er.Error.Code, er.Error.Message)
		}
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(body))
	}

	if out == nil {
		return nil
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w; body=%s", err, string(body))
	}

	return nil
}
