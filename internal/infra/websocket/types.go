// Package websocket provides WebSocket infrastructure for real-time communication.
package websocket

import (
	"encoding/json"
	"time"
)

// MessageType defines the type of WebSocket message.
type MessageType string

const (
	// Client -> Server messages
	MessageTypeSubscribe   MessageType = "subscribe"
	MessageTypeUnsubscribe MessageType = "unsubscribe"
	MessageTypePing        MessageType = "ping"

	// Server -> Client messages
	MessageTypePong         MessageType = "pong"
	MessageTypeSubscribed   MessageType = "subscribed"
	MessageTypeUnsubscribed MessageType = "unsubscribed"
	MessageTypeEvent        MessageType = "event"
	MessageTypeError        MessageType = "error"
)

// Message is the base WebSocket message structure.
type Message struct {
	Type      MessageType     `json:"type"`
	Channel   string          `json:"channel,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Timestamp int64           `json:"timestamp"`
	RequestID string          `json:"request_id,omitempty"`
}

// NewMessage creates a new message with current timestamp.
func NewMessage(msgType MessageType) *Message {
	return &Message{
		Type:      msgType,
		Timestamp: time.Now().UnixMilli(),
	}
}

// WithChannel sets the channel for the message.
func (m *Message) WithChannel(channel string) *Message {
	m.Channel = channel
	return m
}

// WithData sets the data for the message.
func (m *Message) WithData(data any) *Message {
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err == nil {
			m.Data = jsonData
		}
	}
	return m
}

// WithRequestID sets the request ID for the message.
func (m *Message) WithRequestID(id string) *Message {
	m.RequestID = id
	return m
}

// SubscribeRequest represents a subscribe message from client.
type SubscribeRequest struct {
	Channel   string `json:"channel"`
	RequestID string `json:"request_id,omitempty"`
}

// UnsubscribeRequest represents an unsubscribe message from client.
type UnsubscribeRequest struct {
	Channel   string `json:"channel"`
	RequestID string `json:"request_id,omitempty"`
}

// ErrorData represents error information sent to client.
type ErrorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ChannelType represents the type of channel.
type ChannelType string

const (
	// Channel types
	ChannelTypeFinding      ChannelType = "finding"      // finding:{id} - activity updates for a finding
	ChannelTypeScan         ChannelType = "scan"         // scan:{id} - scan progress updates
	ChannelTypeTenant       ChannelType = "tenant"       // tenant:{id} - tenant-wide notifications
	ChannelTypeNotification ChannelType = "notification" // notification:{tenant_id} - notification delivery
	ChannelTypeTriage       ChannelType = "triage"       // triage:{finding_id} - AI triage progress updates
)

// ParseChannel extracts the channel type and ID from a channel string.
// Channel format: "{type}:{id}" e.g., "finding:abc-123"
func ParseChannel(channel string) (ChannelType, string) {
	for i, c := range channel {
		if c == ':' {
			return ChannelType(channel[:i]), channel[i+1:]
		}
	}
	return "", channel
}

// MakeChannel creates a channel string from type and ID.
func MakeChannel(channelType ChannelType, id string) string {
	return string(channelType) + ":" + id
}
