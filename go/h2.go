// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
	"nhooyr.io/websocket"
)

func main() {
	ctx := context.Background()
	testws := true
	h2client := &http.Client{Transport: &http2.Transport{}}
	h1client := &http.Client{Transport: &http.Transport{}}

	var tunnel net.Conn
	var err error

	url := "https://proxy.nile.workers.dev/h2/midway.fly.dev/5001"

	if testws {
		url = "wss://proxy.nile.workers.dev/ws/midway.fly.dev/5001"
		tunnel, err = dialws(ctx, h1client, url)
	} else {
		// url = "https://midway.deno.dev/p/midway.fly.dev/5001"
		tunnel, err = fetch(ctx, h2client, url)
	}
	if err != nil {
		log.Fatalf("send err: %s", err)
	}
	defer tunnel.Close()

	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	log.Printf("req sent %s", url)

	doneCh := make(chan int, 1)
	go func() {
		w.Write([]byte("GET ADDR\r\n"))
	}()
	go func() {
		io.Copy(tunnel, r)
		doneCh <- 0
	}()
	go func() {
		io.Copy(os.Stdout, tunnel)
		doneCh <- 0
	}()

	log.Print("waiting...")
	<-doneCh
	log.Print("fin")
}

func dialws(ctx context.Context, client *http.Client, rurl string) (c net.Conn, err error) {
	hdr := http.Header{
		"x-nile-pip-claim": []string{rurl},
	}
	log.Printf("dial %s", rurl)

	var res *http.Response
	ws, res, err := websocket.Dial(ctx, rurl, &websocket.DialOptions{
		HTTPClient: client,
		HTTPHeader: hdr,
	})
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		log.Printf("ws: code?(%d); err: %v\n", res.StatusCode, err)
		return
	}

	c = websocket.NetConn(ctx, ws, websocket.MessageBinary)
	return
}

// ref: github.com/posener/h2conn/blob/13e7df33ed/client.go

func fetch(ctx context.Context, h2 *http.Client, url string) (net.Conn, error) {
	reader, writer := io.Pipe()

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)
	req.ContentLength = -1
	req.Close = false
	req.GetBody = func() (io.ReadCloser, error) {
		log.Println("h2: get body")
		return io.NopCloser(reader), nil
	}
	log.Println("fetch", req.URL)
	resCh := make(chan io.ReadCloser, 1)
	go func() {
		res, err := h2.Do(req)
		if err != nil || res == nil {
			log.Println("h2: fetch err", err)
			resCh <- nil
			return
		}
		resCh <- res.Body
	}()

	_, cancel := context.WithCancel(ctx)
	conn := &Conn{
		wc:     writer,
		cancel: cancel,
	}
	go conn.captureReader(resCh)
	return conn, nil
}

// ref: github.com/posener/h2conn/blob/13e7df33ed/conn.go

type Conn struct {
	net.Conn
	r      io.Reader
	wc     io.WriteCloser
	cancel context.CancelFunc
	noread int
}

func (c *Conn) captureReader(ch <-chan io.ReadCloser) {
	log.Println("h2: capture reader")
	r, ok := <-ch
	if !ok {
		return
	}
	log.Println("h2: capture reader ok")
	c.r = r
}

func (c *Conn) Write(data []byte) (int, error) {
	log.Println("write", len(data))
	return c.wc.Write(data)
}

func (c *Conn) Read(data []byte) (n int, err error) {
	// log.Println("read?", len(data), c.r != nil)
	if c.r == nil {
		c.noread += 1
		time.Sleep(100 * time.Millisecond)
		if c.noread > 100 {
			log.Println("h2: noread threshold", c.noread)
			return 0, io.ErrNoProgress
		}
		return 0, nil
	}
	/*
		log.Println("read?", c.r != nil)
		if c.r == nil {
			return 0, io.EOF
		}
	*/
	n, err = c.r.Read(data)
	log.Println("h2: read done", n, err)
	return n, err
}

func (c *Conn) Close() error {
	c.cancel()
	return c.wc.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return nil }
func (c *Conn) RemoteAddr() net.Addr               { return nil }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }
