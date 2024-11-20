package protect

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

var (
	PingInterval = 30 * time.Second
	PingTimeout  = 60 * time.Second
)

func init() {
	websocket.DefaultDialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
}

type WebsocketEvent struct {
	nvr          *NVR
	Events       chan *WsMessage
	socket       *websocket.Conn
	disconnected chan bool
}

func NewWebsocketEvent(nvr *NVR) (*WebsocketEvent, error) {
	unifiProtectWebsocket := &WebsocketEvent{
		nvr:          nvr,
		Events:       make(chan *WsMessage),
		disconnected: make(chan bool),
	}

	if !nvr.connected {
		return nil, errors.New("not connected")
	}

	if err := unifiProtectWebsocket.connect(); err != nil {
		return nil, err
	}

	return unifiProtectWebsocket, nil
}

func (l *WebsocketEvent) connect() error {
	if err := l.connectWs(); err != nil {
		return err
	}

	go l.handleReconnect()

	return nil
}

func (l *WebsocketEvent) connectWs() error {
	log.Info("Connecting to WS")
	u := url.URL{
		Scheme: "wss",
		Host:   fmt.Sprintf("%s:%d", l.nvr.host, l.nvr.port),
		Path:   "/proxy/protect/ws/updates",
	}

	headers := http.Header{}
	headers.Add("Cookie", l.nvr.cookies)
	headers.Add("X-CSRF-Token", l.nvr.csrfToken)

	socket, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		return err
	}
	l.socket = socket

	go l.readPump()

	return nil
}

func (l *WebsocketEvent) readPump() {
	socket := l.socket

	defer func() {
		log.Info("Stopping websocket pump", socket.LocalAddr())
		socket.Close()
	}()
	log.Info("Starting websocket pump ", socket.LocalAddr())

	socket.SetPongHandler(func(string) error { socket.SetReadDeadline(time.Now().Add(PingTimeout)); return nil })
	for {
		_, rawMessage, err := socket.ReadMessage()
		if err != nil {
			l.disconnected <- true
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			return
		}
		message, err := DecodeWsMessage(rawMessage)

		if err != nil {
			log.Errorf("Invalid rawMessage %s", err)
			continue
		}

		log.Trace("Pushing new rawMessage from socket to socket channel")
		l.Events <- message
	}
}

func (l *WebsocketEvent) handleReconnect() {
	// If we finish, we restart a reconnect loop
	socket := l.socket


	log.Info("Starting reconnect handler ", socket.LocalAddr())
	defer func() {
		log.Info("Stopping reconnect handler", socket.LocalAddr())
	}()

	for {
		select {
		case <-time.After(PingInterval):
			socket.SetWriteDeadline(time.Now().Add(PingInterval))
			if err := socket.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Errorf("Ping Failure: %s", err)
			}
			
		case <-l.disconnected:
			for {
				log.Warn("Disconnected, reconnecting in 30s")
				time.Sleep(10 * time.Second)

				if err := l.nvr.Authenticate(); err != nil {
					log.Errorf("Error reconnect %s", err)
					continue
				}

				if err := l.connect(); err != nil {
					log.Warnf("Error during reconnection, retrying (%s)", err.Error())
					continue
				}
				return
			}
		}
	}
}
