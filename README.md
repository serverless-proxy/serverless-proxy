### All-in on Serverless

_serverless-proxy_ is a serverless WebSockets and HTTP2 to TCP proxy. Runs out-of-the-box on [Cloudflare Workers](https://workers.dev) and [Deno Deploy](https://deno.com/deploy).

## Transport

`h2.js`, pipes the incoming _readable_ `Request.body` stream from the client to the outgoing _writable_ stream of a TCP socket (created via [cloudflare:socket](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets) or [Deno.connect](https://doc.deno.land/deno/stable/~/Deno.connect)) to a client-specified destination. The _readable_ stream of the destination socket is piped on via `Response.body` back to the client.

`ws.js` transforms WebSockets events into _readable_ (via `WebSocket.onmessage`) and _writable_ (`WebSocket.send`) streams. The _readable_ side of the WebSocket is piped into the outgoing _writable_ stream of the TCP socket to a client-specified destination (as above), whilst the _writable_ side of the WebSocket is piped into the _readable_ stream of the TCP socket.

The transport and destination are conveyed by the client via the URL. This means, no multiplexing, ie *one* destination per h2 / ws connection. Not multiplexing on top of doing [TCP-in-TCP is really poor](https://sshuttle.readthedocs.io/en/stable/how-it-works.html), but we'll endure until a better alternative presents itself (like QUIC, specifically [MASQUE](https://blog.cloudflare.com/building-privacy-into-internet-standards-and-how-to-make-your-app-more-private-today/), for example).

The URL for *h2* (HTTP2) and *ws* (WebSockets) full-duplex tunnels to connect to a *hostname:port* over TCP is of form `https://<sub.domain.workers.dev>/[h2|ws]/<sig>/<hostname>/<port>`. An example client implementation is available in [Deno](test/test.js) for *h2* and [go](go/h1h2.go) for *ws*.

In terms of server code, the flow is: source (h2 / ws) <-> `src/server-[workers|deno].js` <-> [`svc.js`](src/base/svc.js) <->
[`auth.js`](src/base/auth.js) <-> [`h2.js`](src/proxifier/h2.js) / [`ws.js`](src/proxifier/ws.js) <-> destination

The design of this proxy is similar to (but not compliant with) probe-resistant [httpt](https://github.com/sergeyfrolov/httpt).

## Development

```bash
# clone the repository
# install Wrangler CLI (globally)
npm i wrangler@3 -g

# wrangler auth, if necessary
# deploy the code
wrangler deploy

# tunnel with a WHATWG Stream compliant
# client (node, deno, etc), or with websockets
# test websocket proxy with go 1.19 or later
cd ./go
go run ./h1h2.go
# test h2 proxy with deno v1.29+ or node v19+
cd ./test
./test.js
```

## The Rethink Proxy Network
This proxy is deployed to production at `https://ken.rethinkdns.com/` for anti-censorship and anti-surveillance
purposes by the [Rethink Open Source Project](https://github.com/celzero/rethink-app). We are team of 3 engineers
working full-time on a suite of open source tools to help people reclaim their privacy and security on Android.

### Community
[<img src="https://img.shields.io/github/sponsors/serverless-dns"
     alt="GitHub Sponsors">](https://github.com/sponsors/serverless-dns)
- The telegram community is super active and full of crypto-bros. Kidding. We are generally a welcoming bunch. Feel free to get in touch: [t.me/rethinkdns](https://t.me/rethinkdns).
- Or, if you prefer [Matrix](https://matrix.to/#/!jrTSpJiEkFNNBMhSaE:matrix.org) (which is bridged to Telegram).
- Or, email us: [hello@celzero.com](mailto:hello@celzero.com) (we read all emails immediately and reply once we fix the issues being reported).
- We regularly hangout in our subreddit: [r/rethinkdns](https://reddit.com/r/rethinkdns).
- We're also kind of active on the bird app, mostly nerd-sniping other engs or shit-posting about our tech stack: [twitter/rethinkdns](https://twitter.com/rethinkdns).

### Sponsors
[<img src="https://fossunited.org/files/fossunited-white.svg"
     alt="FOSS United"
     height="40">](https://fossunited.org/grants)&emsp;

This project's initial development was sponsored by [FOSS United](https://fossunited.org/grants).
