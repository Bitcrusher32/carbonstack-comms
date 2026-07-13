package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	PayloadSHA256    string `json:"payload_sha256"`
	PayloadSizeBytes int64  `json:"payload_size_bytes"`
}

type EnvelopeRecord struct {
	EnvelopeID        string `json:"envelope_id"`
	SenderDeviceID    string `json:"sender_device_id"`
	RecipientDeviceID string `json:"recipient_device_id"`
	ContentType       string `json:"content_type"`
	ProtocolVersion   string `json:"protocol_version"`
	CiphertextB64     string `json:"ciphertext_b64"`
	PayloadSHA256     string `json:"payload_sha256"`
	PayloadSizeBytes  int64  `json:"payload_size_bytes"`
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

type RelaySpaceResponse struct {
	RelaySpaceID       string `json:"relay_space_id"`
	DisplayLabel       string `json:"display_label"`
	CreatedByAccountID string `json:"created_by_account_id"`
	CreatedByDeviceID  string `json:"created_by_device_id"`
	CreatedAt          string `json:"created_at"`
	DisabledAt         string `json:"disabled_at"`
}

type ListRelaySpacesResponse struct {
	RelaySpaces []RelaySpaceResponse `json:"relay_spaces"`
}

type RelaySpaceInviteResponse struct {
	RelaySpaceInviteID string `json:"relay_space_invite_id"`
	RelaySpaceID       string `json:"relay_space_id"`
	InviteTokenHash    string `json:"invite_token_hash"`
	DisplayCode        string `json:"display_code"`
	WordCode           string `json:"word_code"`
	CreatedByMemberID  string `json:"created_by_member_id"`
	CreatedAt          string `json:"created_at"`
	ExpiresAt          string `json:"expires_at"`
	MaxClaims          *int   `json:"max_claims,omitempty"`
	ClaimCount         int    `json:"claim_count"`
	State              string `json:"state"`
	Note               string `json:"note"`
}

type CreateRelaySpaceInviteResponse struct {
	RelaySpaceInvite RelaySpaceInviteResponse `json:"relay_space_invite"`
	InviteToken      string                   `json:"invite_token"`
}

type CreateRelaySpaceInviteInput struct {
	RelaySpaceInviteID string `json:"relay_space_invite_id,omitempty"`
	InviteToken        string `json:"invite_token,omitempty"`
	InviteTokenHash    string `json:"invite_token_hash,omitempty"`
	DisplayCode        string `json:"display_code,omitempty"`
	WordCode           string `json:"word_code,omitempty"`
	CreatedByMemberID  string `json:"created_by_member_id,omitempty"`
	ExpiresAt          string `json:"expires_at,omitempty"`
	MaxClaims          *int   `json:"max_claims,omitempty"`
	State              string `json:"state,omitempty"`
	Note               string `json:"note,omitempty"`
}

type UpdateRelaySpaceMemberStateInput struct {
	TargetState string `json:"target_state"`
}

type RelaySpaceMemberStateResponse struct {
	RoutingMember            RelaySpaceMemberResponse `json:"routing_member"`
	PreviousState            string                   `json:"previous_state"`
	CurrentState             string                   `json:"current_state"`
	TransitionClassification string                   `json:"transition_classification"`
	Idempotent               bool                     `json:"idempotent"`
	TransitionedAt           string                   `json:"transitioned_at,omitempty"`
}

type ClaimRelaySpaceInviteInput struct {
	InviteToken  string `json:"invite_token"`
	AccountID    string `json:"account_id"`
	DeviceID     string `json:"device_id"`
	DisplayLabel string `json:"display_label,omitempty"`
}

type ClaimRelaySpaceInviteResponse struct {
	RelaySpace          RelaySpaceResponse       `json:"relay_space"`
	RoutingMember       RelaySpaceMemberResponse `json:"routing_member"`
	RelaySpaceInvite    RelaySpaceInviteResponse `json:"relay_space_invite"`
	ClaimClassification string                   `json:"claim_classification"`
	Idempotent          bool                     `json:"idempotent"`
	ClaimConsumed       bool                     `json:"claim_consumed"`
}

type RelaySpaceMemberResponse struct {
	RoutingMemberID string `json:"routing_member_id"`
	RelaySpaceID    string `json:"relay_space_id"`
	AccountID       string `json:"account_id"`
	DeviceID        string `json:"device_id"`
	DisplayLabel    string `json:"display_label"`
	State           string `json:"state"`
	JoinedAt        string `json:"joined_at"`
	LastSeenAt      string `json:"last_seen_at"`
	DisabledAt      string `json:"disabled_at"`
}

type RegisterRelaySpaceMemberInput struct {
	RoutingMemberID string `json:"routing_member_id,omitempty"`
	AccountID       string `json:"account_id"`
	DeviceID        string `json:"device_id,omitempty"`
	DisplayLabel    string `json:"display_label,omitempty"`
	State           string `json:"state,omitempty"`
	LastSeenAt      string `json:"last_seen_at,omitempty"`
}

type ListRelaySpaceMembersResponse struct {
	RelaySpaceID string                     `json:"relay_space_id"`
	Members      []RelaySpaceMemberResponse `json:"members"`
}

type SubmitRelaySpaceEnvelopeResponse struct {
	EnvelopeID       string `json:"envelope_id"`
	RelaySpaceID     string `json:"relay_space_id"`
	DeliveryState    string `json:"delivery_state"`
	ServerReceivedAt string `json:"server_received_at"`
	PayloadSHA256    string `json:"payload_sha256"`
	PayloadSizeBytes int64  `json:"payload_size_bytes"`
}

type RelaySpaceEnvelopeRecord struct {
	EnvelopeID        string `json:"envelope_id"`
	RelaySpaceID      string `json:"relay_space_id"`
	SenderDeviceID    string `json:"sender_device_id"`
	RecipientDeviceID string `json:"recipient_device_id"`
	ContentType       string `json:"content_type"`
	ProtocolVersion   string `json:"protocol_version"`
	CiphertextB64     string `json:"ciphertext_b64"`
	PayloadSHA256     string `json:"payload_sha256"`
	PayloadSizeBytes  int64  `json:"payload_size_bytes"`
	ClientCreatedAt   string `json:"client_created_at"`
	ServerReceivedAt  string `json:"server_received_at"`
	DeliveryState     string `json:"delivery_state"`
}

type RelaySpaceInboxResponse struct {
	RelaySpaceID string                     `json:"relay_space_id"`
	DeviceID     string                     `json:"device_id"`
	Envelopes    []RelaySpaceEnvelopeRecord `json:"envelopes"`
}

type AckRelaySpaceEnvelopeResponse struct {
	EnvelopeID     string `json:"envelope_id"`
	RelaySpaceID   string `json:"relay_space_id"`
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

func (c CypherClient) CreateRelaySpace(relaySpaceID string, displayLabel string, createdByAccountID string, createdByDeviceID string) (RelaySpaceResponse, error) {
	var resp RelaySpaceResponse
	req := map[string]string{
		"relay_space_id":        relaySpaceID,
		"display_label":         displayLabel,
		"created_by_account_id": createdByAccountID,
		"created_by_device_id":  createdByDeviceID,
	}
	err := postJSON(c.endpoint("/v0/relay-spaces"), req, &resp)
	return resp, err
}

func (c CypherClient) ListRelaySpaces() (ListRelaySpacesResponse, error) {
	var resp ListRelaySpacesResponse
	err := getJSON(c.endpoint("/v0/relay-spaces"), &resp)
	return resp, err
}

func (c CypherClient) GetRelaySpace(relaySpaceID string) (RelaySpaceResponse, error) {
	var resp RelaySpaceResponse
	err := getJSON(c.endpoint("/v0/relay-spaces/"+url.PathEscape(relaySpaceID)), &resp)
	return resp, err
}

func (c CypherClient) CreateRelaySpaceInvite(relaySpaceID string, input CreateRelaySpaceInviteInput) (CreateRelaySpaceInviteResponse, error) {
	var resp CreateRelaySpaceInviteResponse
	err := postJSON(c.endpoint("/v0/relay-spaces/"+url.PathEscape(relaySpaceID)+"/invites"), input, &resp)
	return resp, err
}

func (c CypherClient) UpdateRelaySpaceMemberState(
	relaySpaceID string,
	routingMemberID string,
	input UpdateRelaySpaceMemberStateInput,
) (RelaySpaceMemberStateResponse, error) {
	var resp RelaySpaceMemberStateResponse
	err := postJSON(
		c.endpoint(
			"/v0/relay-spaces/"+
				url.PathEscape(relaySpaceID)+
				"/members/"+
				url.PathEscape(routingMemberID)+
				"/state",
		),
		input,
		&resp,
	)
	return resp, err
}

func (c CypherClient) ClaimRelaySpaceInvite(
	input ClaimRelaySpaceInviteInput,
) (ClaimRelaySpaceInviteResponse, error) {
	var resp ClaimRelaySpaceInviteResponse
	err := postJSON(
		c.endpoint("/v0/relay-spaces/invites/claim"),
		input,
		&resp,
	)
	return resp, err
}

func (c CypherClient) RegisterRelaySpaceMember(relaySpaceID string, input RegisterRelaySpaceMemberInput) (RelaySpaceMemberResponse, error) {
	var resp RelaySpaceMemberResponse
	err := postJSON(c.endpoint("/v0/relay-spaces/"+url.PathEscape(relaySpaceID)+"/members"), input, &resp)
	return resp, err
}

func (c CypherClient) ListRelaySpaceMembers(relaySpaceID string) (ListRelaySpaceMembersResponse, error) {
	var resp ListRelaySpaceMembersResponse
	err := getJSON(c.endpoint("/v0/relay-spaces/"+url.PathEscape(relaySpaceID)+"/members"), &resp)
	return resp, err
}

func (c CypherClient) SubmitRelaySpaceEnvelope(relaySpaceID string, senderDeviceID string, recipientDeviceID string, contentType string, protocolVersion string, ciphertextB64 string, clientCreatedAt string) (SubmitRelaySpaceEnvelopeResponse, error) {
	var resp SubmitRelaySpaceEnvelopeResponse
	req := map[string]string{
		"sender_device_id":    senderDeviceID,
		"recipient_device_id": recipientDeviceID,
		"content_type":        contentType,
		"protocol_version":    protocolVersion,
		"ciphertext_b64":      ciphertextB64,
		"client_created_at":   clientCreatedAt,
	}
	err := postJSON(c.endpoint("/v0/relay-spaces/"+url.PathEscape(relaySpaceID)+"/envelopes"), req, &resp)
	return resp, err
}

func (c CypherClient) RelaySpaceInbox(relaySpaceID string, deviceID string) (RelaySpaceInboxResponse, error) {
	var resp RelaySpaceInboxResponse
	err := getJSON(c.endpoint("/v0/relay-spaces/"+url.PathEscape(relaySpaceID)+"/devices/"+url.PathEscape(deviceID)+"/envelopes"), &resp)
	return resp, err
}

func (c CypherClient) AckRelaySpaceEnvelope(relaySpaceID string, envelopeID string, recipientDeviceID string) (AckRelaySpaceEnvelopeResponse, error) {
	var resp AckRelaySpaceEnvelopeResponse
	req := map[string]string{
		"recipient_device_id": recipientDeviceID,
	}
	err := postJSON(c.endpoint("/v0/relay-spaces/"+url.PathEscape(relaySpaceID)+"/envelopes/"+url.PathEscape(envelopeID)+"/ack"), req, &resp)
	return resp, err
}

func (c CypherClient) endpoint(path string) string {
	return strings.TrimRight(c.ServerURL, "/") + path
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
