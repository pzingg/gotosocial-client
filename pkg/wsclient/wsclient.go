package wsclient

// From github.com/webdeveloppro/golang-websocket-client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Send pings to peer with this period
const pingPeriod = 30 * time.Second

// Message represents one streamed message from GoToSocial.
type GtsMessage struct {
	// All the stream types this message should be delivered to.
	Stream []string `json:"stream"`
	// The event type of the message (update/delete/notification etc)
	Event string `json:"event"`
	// The actual payload of the message. In case of an update or notification, this will be a JSON string.
	Payload string `json:"payload"`
}

// WebSocketClient return websocket client connection
type WebSocketClient struct {
	Ctx       context.Context
	CtxCancel context.CancelFunc
	Messages  chan GtsMessage

	configStr string
	sendBuf   chan []byte
	mu        sync.RWMutex
	wsconn    *websocket.Conn
}

// NewWebSocketClient create new websocket connection
func NewWebSocketClient(ctx context.Context, wsUrl string, msgChan chan GtsMessage) *WebSocketClient {
	conn := WebSocketClient{
		configStr: wsUrl,
		sendBuf:   make(chan []byte, 1),
		Messages:  msgChan,
	}
	conn.Ctx, conn.CtxCancel = context.WithCancel(ctx)
	defer conn.CtxCancel()

	fmt.Printf("Connecting to %s\n", wsUrl)

	go conn.Listen()
	go conn.listenWrite()
	go conn.ping()
	return &conn
}

func (conn *WebSocketClient) Connect() *websocket.Conn {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.wsconn != nil {
		return conn.wsconn
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ; ; <-ticker.C {
		select {
		case <-conn.Ctx.Done():
			return nil
		default:
			ws, _, err := websocket.DefaultDialer.Dial(conn.configStr, nil)
			if err != nil {
				conn.log("connect", err, fmt.Sprintf("Cannot connect to websocket: %s", conn.configStr))
				continue
			}
			conn.log("connect", nil, fmt.Sprintf("Connected to websocket %s", conn.configStr))
			conn.wsconn = ws
			return conn.wsconn
		}
	}
}

func (conn *WebSocketClient) Listen() {
	conn.log("listen", nil, fmt.Sprintf("listen for the messages: %s", conn.configStr))
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-conn.Ctx.Done():
			return
		case <-ticker.C:
			for {
				ws := conn.Connect()
				if ws == nil {
					err := errors.New("conn.ws is nil")
					conn.log("listen", err, "No websocket connection")
					return
				}
				msgType, msgBytes, err := ws.ReadMessage()
				if err != nil {
					if websocket.IsCloseError(err, 1006) {
						conn.log("listen", err, "Peer closed connection")
						conn.Stop()
						return
					} else {
						conn.log("listen", err, "Cannot read websocket message")
						conn.closeWs()
						break
					}
				}
				switch msgType {
				// TextMessage denotes a text data message. The text message payload is
				// interpreted as UTF-8 encoded text data.
				case websocket.TextMessage:
					var message GtsMessage
					err = json.Unmarshal(msgBytes, &message)
					if err != nil {
						conn.log("listen", err, fmt.Sprintf("websocket TextMessage: %d bytes", len(msgBytes)))
					} else {
						conn.log("listen", err, fmt.Sprintf("websocket GtsMessage: %s", message.Event))
					}
					conn.Messages <- message
				// BinaryMessage denotes a binary data message.
				case websocket.BinaryMessage:
					conn.log("listen", nil, fmt.Sprintf("websocket BinaryMessage: %d bytes", len(msgBytes)))
				// CloseMessage denotes a close control message. The optional message
				// payload contains a big-endian uint16 numeric close code and text.
				case websocket.CloseMessage:
					conn.log("listen", nil, fmt.Sprintf("websocket CloseMessage: %d bytes", len(msgBytes)))
				// PingMessage denotes a ping control message. The optional message payload
				// is UTF-8 encoded text.
				case websocket.PingMessage:
					conn.log("listen", nil, fmt.Sprintf("websocket PingMessage: '%s'", string(msgBytes)))
				// PongMessage denotes a pong control message. The optional message payload
				// is UTF-8 encoded text.
				case websocket.PongMessage:
					conn.log("listen", nil, fmt.Sprintf("websocket PongMessage: '%s'", string(msgBytes)))
				default:
					conn.log("listen", nil, fmt.Sprintf("websocket unknown type %d: %d bytes", msgType, len(msgBytes)))
				}
			}
		}
	}
}

// Write data to the websocket server
func (conn *WebSocketClient) Write(payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		conn.log("Write", err, "Json encoding")
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
	defer cancel()

	conn.log("Write", nil, fmt.Sprintf("Sending payload %d chars to channel", len(data)))
	for {
		select {
		case conn.sendBuf <- data:
			return nil
		case <-ctx.Done():
			err := errors.New("context canceled")
			conn.log("Write", err, "Done")
			return err
		}
	}
}

func (conn *WebSocketClient) listenWrite() {
	for data := range conn.sendBuf {
		ws := conn.Connect()
		if ws == nil {
			err := errors.New("conn.ws is nil")
			conn.log("listenWrite", err, "No websocket connection")
			continue
		}

		err := ws.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			conn.log("listenWrite", nil, "WebSocket Write Error")
		}
		conn.log("listenWrite", nil, fmt.Sprintf("send: %s", data))
	}
}

// Close will send close message and shutdown websocket connection
func (conn *WebSocketClient) Stop() {
	conn.CtxCancel()
	conn.closeWs()
}

// Close will send close message and shutdown websocket connection
func (conn *WebSocketClient) closeWs() {
	conn.mu.Lock()
	if conn.wsconn != nil {
		conn.log("closeWs", nil, "Sending close message and closing connection")
		conn.wsconn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		conn.wsconn.Close()
		conn.wsconn = nil
	}
	conn.mu.Unlock()
}

func (conn *WebSocketClient) ping() {
	conn.log("ping", nil, "ping pong started")
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ws := conn.Connect()
			if ws == nil {
				continue
			}
			conn.log("ping", nil, "Sending ping")
			err := conn.wsconn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(pingPeriod/2))
			if err != nil {
				conn.log("ping", err, "Closing connection")
				conn.closeWs()
			}
		case <-conn.Ctx.Done():
			return
		}
	}
}

// Log print log statement
// In real word I would recommend to use zerolog or any other solution
func (conn *WebSocketClient) log(f string, err error, msg string) {
	if err != nil {
		fmt.Printf("[ERROR] %s, err: %v, msg: %s\n", f, err, msg)
	} else {
		fmt.Printf("[INFO] %s, %s\n", f, msg)
	}
}
