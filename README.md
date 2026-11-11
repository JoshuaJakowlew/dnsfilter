# dnsfilter

A local DNS forwarder with a domain blocklist. It listens for DNS requests, checks the queried name against the blacklist, and passes the query to an upstream resolver if filter was passed.

The server is small and has little else in it. It is meant for a home network: run it on a router or on a machine in the LAN, and point clients at its address for DNS.

## How it works

Each query takes one pass.

1. A UDP packet with DNS request arrives.
2. The name is checked against the list together with its parent suffixes. An entry `example.com` blocks both `example.com` and `a.example.com`. An entry `a.example.com` does not block `example.com`, and `example.com.evil.test` is not blocked by `example.com`.
3. If the name is listed, the upstream server is not contacted. The client gets an immediate response with its own query id.
4. If the name is not listed, the client address and the original packet id are stored. In the outgoing copy the id is replaced with a free slot number, and the packet is sent to the address from `-r`.
5. A reply from upstream is accepted only when the slot number and the hash of the question (name, type, class) match what was sent. The client receives the same packet with the original id restored. A foreign or late reply that lands in a slot already reused by another query is dropped.

Unanswered queries live for 5 seconds. Expired slots are freed once a second. Up to 65536 queries can be in flight at once. There is no cache and every allowed query goes upstream again.

A packet whose question count is not exactly one, or whose question name cannot be parsed, is not forwarded and gets no reply. Name compression pointers in the question section are not parsed. Ordinary clients do not encode the question that way.

An error on a single packet is printed to stdout and does not stop the process. `SIGINT` and `SIGTERM` shut it down.

## Build and run

```sh
cargo build --release
./target/release/dnsfilter -f blocklist.txt -p 53 -r 1.1.1.1:53
```

It listens on `0.0.0.0`, all IPv4 interfaces. No IPv6 socket is opened. `AAAA` queries are still handled normally: the transport to the client is IPv4 UDP, and the record type belongs to the answer.

On Linux, port 53 usually needs root or the `CAP_NET_BIND_SERVICE` capability. For a trial, a free port such as 5353 is easier, with the same port set as the client's DNS.

At startup the file is read in full and the number of loaded names is printed to stdout. The file is not reread while the process is running. A new list takes effect after a restart.

Full flag list: `dnsfilter --help`.

## Arguments

All three are required.


| Flag                  | Value                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------- |
| `-f`, `--filter-path` | path to the file of blocked domains                                                   |
| `-p`, `--port`        | local UDP port                                                                        |
| `-r`, `--remote-addr` | upstream DNS address including the port, for example `9.9.9.9:53` or `192.168.1.1:53` |


The upstream address is an ordinary resolver: a router, the ISP, or a public server. dnsfilter does not recurse.

## Domain list

A text file, one name per line:

```
ads.example.com
tracker.example.net
doubleclick.net
```

Empty lines are skipped. Spaces and `\r` at the edges of a line are trimmed. Case does not matter. A trailing dot is allowed and dropped, so `Example.COM.` and `example.com` are the same name.

There are no comments and no hosts-file format. A line `0.0.0.0 ads.example.com` or `# comment` is an invalid name: the process exits with an error and does not bind the port. The same happens for a repeated name, a label longer than 63 bytes, or a name that does not fit in 255 bytes of DNS encoding. An empty label (`example..com`) is an error too.

## Reply for a blocked name

- `A` gets `0.0.0.0`
- `AAAA` gets `::`
- any other type gets `NOERROR` with no records in the answer section (NODATA)

The TTL of the substituted addresses is 60 seconds. The response code is not `NXDOMAIN`: for the client the name exists, but it points nowhere. If an EDNS `OPT` record stood immediately after the question, the reply includes an empty `OPT` with UDP payload size 1232.