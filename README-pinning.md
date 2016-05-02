
This is an implementation of [draft-sheffer-tls-pinning-ticket](https://datatracker.ietf.org/doc/draft-sheffer-tls-pinning-ticket/) and a fork of the [Mint](https://github.com/bifurcation/mint) TLS 1.3 implementation.

# Overview

This proposed solution **pins** (fixes) the server's identity by only reconnecting a client to the server if the server can prove that it has access to a long-term key and therefore can decrypt a **ticket** stored on the client. This is more secure than simply relying on the server's PKI certificate, and easier to use than [HPKP](https://tools.ietf.org/html/rfc7469).

# This is Not Production-Ready

First, because an Internet draft is not a published standard, and very likely will change before it is published.

And second, because we use a database (SQLite) to store the client-side ticket and the server-side protection keys. People will probably prefer to use file storage for both.

# Usage


```
go run bin/mint-server/main.go -keyfile serverKey.pem -certfile serverCert.pem -pinning -pinning-database server.db -servername myserver &

go run bin/mint-client/main.go -pinning -pinning-database client.db &
```

Add the flag ``-pinning-rampdown`` on the server side to run the server in rampdown mode, where it does not return a new ticket to the client.

# Administrative Commands

## Server-Side
Create initial protection key and rotate protection key (currently run the same code).

```
go run bin/mint-server/main.go -pinning -pinning-database server.db -pinning-create-server-key

go run bin/mint-server/main.go -pinning -pinning-database server.db -pinning-rotate-server-key
```

## Client-Side
Delete the ticket for ``localhost`` and delete all tickets.

```
go run bin/mint-client/main.go -pinning -pinning-database client.db -pinning-clear-ticket localhost

go run bin/mint-client/main.go -pinning -pinning-database client.db -pinning-clear-all-tickets
```

# Debugging
```
export MINT_LOG='pinning'
```
