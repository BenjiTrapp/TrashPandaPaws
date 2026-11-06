# Putting a redirector in front of the team server

> **Short answer.** Yes, and it is safe to get wrong. Point the proxy at the
> **agent socket** (`--port`, default `8443`) and nothing else. The operator
> interface (`--operator-port`, default `8444`) is a different socket, bound
> to loopback, and the server refuses it to anything that arrives on the
> agent socket -- so a redirector with mistaken rules still cannot reach the
> GUI or the `/api/*` routes. Neither project this page assesses is vendored.

---

## What a redirector buys, and what it does not

A **redirector** is a host that takes the beacon's request and forwards it to
the team server. What it buys is **address-hiding**: a defender who catches a
beacon and reads its callback address learns the redirector's address, not the
team server's. Burn the redirector, keep the team server.

That requires a **second host**. On a single machine a redirector forwarding
to `127.0.0.1` hides nothing -- the same machine answers either way. The
change that carries the security property is the socket split; the
redirector is additive.

What it does not do:

- **It does not filter.** Every request goes to the agent socket unchanged.
  That is deliberate: a Malleable C2 profile moves the beacon's URIs
  anywhere, so a path allow-list in the proxy would reject legitimate
  beacons, and a block list kept in a proxy's configuration is a safety
  property in a file a user edits. The property lives in the server, on the
  socket.
- **It never holds the encryption key.** The proxy forwards the body; it
  does not need `RACCOON_KEY` and the examples below never mention it. What
  it can read is ciphertext and the request line.
- **It does not replace the operator token.** The token guards the interface,
  and the interface is not served on the socket the proxy talks to.

---

## The two sockets

| Flag | Default | What it is | Point the proxy at it? |
|---|---|---|---|
| `--host` | `0.0.0.0` | the agent socket's address | the address, yes |
| `--port` | `8443` | the agent socket's port -- the endpoint remote agents call | **yes** |
| `--operator-host` | `127.0.0.1` | the operator interface's address (loopback only) | no |
| `--operator-port` | `8444` | the operator interface's port | **never** |

The server decides by the socket a request arrived on, not by its path. On
the agent socket only the beacon handler answers; everything else -- the
page, `/api/*`, `/static/*` -- is given the same cover reply as `GET /`,
whatever the path and whatever token is presented. So a proxy cannot reach
the interface, even if its rules are wrong.

This holds **only while the two ports differ**. Setting `--operator-port`
equal to `--port` puts both audiences back on one socket and the policy is
inert; do not do that behind a redirector.

On the redirector's side of the link, bind the agent socket to the private
address the redirector reaches it on, so that nothing else can call it
directly:

```bash
# RACCOON_KEY must be set in the environment: the server refuses to start
# without one, and the key does not belong on the command line (it shows in ps).
python3 software/c2/server.py --host 10.8.0.2 --port 8443
```

`10.8.0.2` stands for the team server's address on the private link between
the two hosts (WireGuard, an SSH tunnel, a cloud VPC -- your choice). Replace
it everywhere below.

---

## nginx

Put this in `/etc/nginx/conf.d/raccoon-redirector.conf`. The `proxy_pass` line
is the only place the team server appears, and it names the agent socket.

```nginx
server_tokens off;

server {
    listen 443 ssl;
    server_name redirector.example.com;

    ssl_certificate     /etc/ssl/redirector/fullchain.pem;
    ssl_certificate_key /etc/ssl/redirector/privkey.pem;

    client_max_body_size 16m;

    location / {
        proxy_pass http://10.8.0.2:8443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }
}
```

`proxy_pass` has no URI part, so nginx passes the request path through
exactly as received. `16m` is a choice, not a measured figure: set it to the
largest file you expect a beacon to send, because the server itself has no
request-size cap (see *Known limits* in [`AGENT.md`](AGENT.md)).

If the hop to the team server crosses a network you do not trust, run the
server with `--ssl --cert <pem> --certkey <key>` and **pin** that certificate
rather than skipping verification. Replace the `proxy_pass` line with:

```nginx
        proxy_pass https://10.8.0.2:8443;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/ssl/redirector/teamserver.pem;
        proxy_ssl_name teamserver.internal;
```

where `teamserver.pem` is the server's certificate and `teamserver.internal`
is a name in its subject alternative names.

## Caddy

```caddyfile
redirector.example.com {
    request_body {
        max_size 16MB
    }

    reverse_proxy 10.8.0.2:8443 {
        transport http {
            dial_timeout 5s
            response_header_timeout 60s
        }
    }
}
```

Caddy passes the path and the `Host` header through unchanged and adds
`X-Forwarded-For` itself. The pinned-certificate form of the same block:

```caddyfile
    reverse_proxy https://10.8.0.2:8443 {
        transport http {
            tls_trust_pool file {
                pem_file /etc/ssl/redirector/teamserver.pem
            }
            tls_server_name teamserver.internal
            dial_timeout 5s
            response_header_timeout 60s
        }
    }
```

## Reaching the GUI

Not through the redirector. The operator interface is loopback-only on the
team server; from another machine, forward it over SSH, which is also what the
startup banner prints:

```bash
ssh -L 8444:127.0.0.1:8444 <user>@<this-host>
# then open http://localhost:8444
```

(`https://` if the server was started with `--ssl`.)

---

## What was and was not tested

**Tested on this machine.** Two sockets were started on ephemeral ports with
a random key in the environment, and every request below carried a **valid**
operator token:

| Request | Agent socket | Operator socket |
|---|---|---|
| `GET /` | `{"status":"ok","version":"2.1.0"}` | `text/html` — the interface |
| `GET /api/agents` | `{"status":"ok","version":"2.1.0"}` | `[]` — the real, empty fleet |
| `GET /api/server/config` | `{"status":"ok","version":"2.1.0"}` | *(not requested)* |

So the claim this page rests on is measured, not argued: **a valid token does
not help on the agent socket.** The token also appeared zero times in the body
of `GET /`.

The four flag names and their defaults in the table above were read back out
of the argument parser in `software/c2/server.py`, not from memory. The
`ssh -L` line is the form the startup banner prints, confirmed by starting the
server and reading it.

**Not tested: the nginx and Caddy configuration itself.** Neither program is
installed here, so neither file was syntax-checked and no request has ever
been proxied through them. They were written from each project's
documentation. Treat these four directives as the ones to check first against
your own version:

- nginx: `proxy_ssl_verify`, `proxy_ssl_trusted_certificate`, `proxy_ssl_name`
- Caddy: `tls_trust_pool file { pem_file … }` — this is recent syntax; older
  Caddy used `tls_trusted_ca_certs`, so check it against the version you run

**Not tested: the address-hiding property.** No two-host deployment was built.
That a defender who catches a beacon learns the redirector's address and not
the team server's follows from the beacon's callback address being the
redirector's, but it is reasoning, not a measurement.

One thing worth knowing from doing this: the banner goes to **stdout**, which
Python buffers when it is not a terminal. Start the server with its output
redirected to a file and the banner may not appear until the process exits —
`python3 -u` or a terminal shows it immediately. The log lines go to stderr
and are not affected.

---

## The two projects that were considered

The question that prompted this page named two projects. Neither is vendored.
Both are permissively licensed, so copying either would have been **legal**;
the reasons below are about fit, not permission. This repository carries no
`LICENSE` file of its own yet (listed in *Known limits*), which is one more
reason to be exact about whose code is whose: nothing from either project is
in this tree.

### lambda-redirector -- MIT -- the wrong tool

[ModusCreateOrg/lambda-redirector](https://github.com/ModusCreateOrg/lambda-redirector)
(MIT licence) is an AWS Lambda and API Gateway stack that **redirects a whole
website from one domain to another**. It answers `301` or `302` with a
`Location` header; its only parameters are `NewDomain` and `HTTPResponse`,
and `HTTPResponse` may be `301` or `302` and nothing else.

That is not a smaller version of what a beacon needs, it is a different
problem:

- A beacon `POST`s an encrypted body. A redirect cannot carry a body to a
  second address; a `301` or `302` on a `POST` is commonly followed as a
  `GET`, which drops it.
- Even a redirect that was followed would send the beacon to the **team
  server's own address**, which is the thing a redirector exists to hide.

### InfraGuard -- BSD-2-Clause -- the right category, not vendored

[Whispergate/InfraGuard](https://github.com/Whispergate/InfraGuard)
(BSD 2-Clause licence) is the right kind of tool: a reverse proxy that sits
between the internet and a team server. Because it is BSD-licensed it could
legally be vendored, unlike ARTEX, which is AGPL and so was taken for its
ideas only. It is not vendored, for three reasons:

1. **It is a product.** Redis for shared state, a Helm chart, blue-green
   Terraform rotation across cloud providers, 29 plugins, and an optional
   Ollama integration. Beside a Raspberry Pi drop-box it would dwarf the thing
   it protects.
2. **Its headline feature does not apply.** InfraGuard validates inbound
   requests against a malleable profile for Cobalt Strike, Mythic, Brute Ratel
   C4, Sliver, Havoc, Nighthawk and PoshC2. Raccoon's own profile format is
   not among them, so the feature that justifies the dependency has nothing to
   read.
3. **It would move a safety property into a file a user edits.** Making the
   operator interface unreachable from the agent side is enforced here by the
   server, on the socket. Putting a block on `GET /` into an external proxy's
   rules would place that property in configuration -- the trade-off this
   project already rejected in ARTEX's `guard`.

If you want what InfraGuard does -- scanner filtering, JA3 matching, decoy
pages, burn detection -- run it in front of this server and point it at the
agent socket exactly as above. It remains the better-maintained answer to that
need than anything written here.
