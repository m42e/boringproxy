package boringproxy

import (
    "fmt"
    "io"
    "net"
    "net/http"
    "time"

    "github.com/gorilla/websocket"
)

func proxyRequest(w http.ResponseWriter, r *http.Request, tunnel Tunnel, httpClient *http.Client, address string, port int, behindProxy bool) {

	if tunnel.AuthUsername != "" || tunnel.AuthPassword != "" {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header()["WWW-Authenticate"] = []string{"Basic"}
			w.WriteHeader(401)
			return
		}

		if username != tunnel.AuthUsername || password != tunnel.AuthPassword {
			w.Header()["WWW-Authenticate"] = []string{"Basic"}
			w.WriteHeader(401)
			// TODO: should probably use a better form of rate limiting
			time.Sleep(2 * time.Second)
			return
		}
	}

	downstreamReqHeaders := r.Header.Clone()

	upstreamAddr := fmt.Sprintf("%s:%d", address, port)
	upstreamUrl := fmt.Sprintf("http://%s%s", upstreamAddr, r.URL.RequestURI())

	upstreamReq, err := http.NewRequest(r.Method, upstreamUrl, r.Body)
	if err != nil {
		errMessage := fmt.Sprintf("%s", err)
		w.WriteHeader(500)
		io.WriteString(w, errMessage)
		return
	}

	// ContentLength needs to be set manually because otherwise it is
	// stripped by golang. See:
	// https://golang.org/pkg/net/http/#Request.Write
	upstreamReq.ContentLength = r.ContentLength

	upstreamReq.Header = downstreamReqHeaders

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	upstreamReq.Header["X-Forwarded-Proto"] = []string{scheme}

	upstreamReq.Header["X-Forwarded-Host"] = []string{r.Host}

	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		errMessage := fmt.Sprintf("%s", err)
		w.WriteHeader(500)
		io.WriteString(w, errMessage)
		return
	}

	xForwardedFor := remoteHost

	if behindProxy {
		xForwardedFor := downstreamReqHeaders.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			xForwardedFor = xForwardedFor + ", " + remoteHost
		}
	}

	upstreamReq.Header.Set("X-Forwarded-For", xForwardedFor)
	upstreamReq.Header.Set("Forwarded", fmt.Sprintf("for=%s", remoteHost))

	// TODO: This might need to be more generic, but using r.Host. However,
	// I think that may have security implications for things like DNS
	// rebinding attacks. Not sure.
	upstreamReq.Host = tunnel.Domain

	upstreamRes, err := httpClient.Do(upstreamReq)
	if err != nil {
		errMessage := fmt.Sprintf("%s", err)
		w.WriteHeader(502)
		io.WriteString(w, errMessage)
		return
	}
	defer upstreamRes.Body.Close()

	var forwardHeaders map[string][]string

	if r.ProtoMajor > 1 {
		forwardHeaders = stripConnectionHeaders(upstreamRes.Header)
	} else {
		forwardHeaders = upstreamRes.Header
	}

	downstreamResHeaders := w.Header()

	for k, v := range forwardHeaders {
		downstreamResHeaders[k] = v
	}

	w.WriteHeader(upstreamRes.StatusCode)
	io.Copy(w, upstreamRes.Body)
}

func isWebSocket(r *http.Request) bool {
    return websocket.IsWebSocketUpgrade(r)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, address string, port int) {
    var upgrader = websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool {
            return true
        },
    }

    upstreamAddr := fmt.Sprintf("%s:%d", address, port)
    upstreamConn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("ws://%s%s", upstreamAddr, r.URL.RequestURI()), r.Header)
    if err != nil {
        http.Error(w, "Error contacting backend http.Status server.",http.StatusInternalServerError)
        return
    }
    defer upstreamConn.Close()

    downstreamConn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        http.Error(w, "Error upgrading connection.", http.StatusInternalServerError)
        return
    }
    defer downstreamConn.Close()

    errorChan := make(chan error, 2)

    go copyWebSocket(upstreamConn, downstreamConn, errorChan)
    go copyWebSocket(downstreamConn, upstreamConn, errorChan)
    <-errorChan
}

func copyWebSocket(dst, src *websocket.Conn, errorChan chan error) {
    for {
        messageType, p, err := src.ReadMessage()
        if err != nil {
            errorChan <- err
            return
        }
        if err := dst.WriteMessage(messageType, p); err != nil {
            errorChan <- err
            return
        }
    }
}

// Need to strip out headers that shouldn't be forwarded from HTTP/1.1 to
// HTTP/2. See https://tools.ietf.org/html/rfc7540#section-8.1.2.2
var connectionHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade",
}

func stripConnectionHeaders(headers map[string][]string) map[string][]string {
	forwardHeaders := make(map[string][]string)

	for k, v := range headers {
		if stringInArray(k, connectionHeaders) {
			continue
		}

		forwardHeaders[k] = v
	}

	return forwardHeaders
}
