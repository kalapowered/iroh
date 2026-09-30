# iroh-dns-server

A server that functions as a [pkarr](https://github.com/Nuhvi/pkarr/) relay and
[DNS](https://de.wikipedia.org/wiki/Domain_Name_System) server.

This server compiles to a binary `iroh-dns-server`. It needs a config file, of
which there are two examples included:

- [`config.dev.toml`](./config.dev.toml) - suitable for local development
- [`config.prod.toml`](./config.prod.toml) - suitable for production, after
  adjusting the domain names and IP addresses

The server will expose the following services:

- A DNS server listening on UDP and TCP for DNS queries
- A HTTP and/or HTTPS server which provides the following routes:
  - `/pkarr`: `GET` and `PUT` for pkarr signed packets
  - `/dns-query`: Answer DNS queries over
    [DNS-over-HTTPS](https://datatracker.ietf.org/doc/html/rfc8484)

All received and valid pkarr signed packets will be served over DNS. The pkarr
packet origin will be appended with the origin as configured by this server.

## Limits

- **Publications** (`PUT /pkarr/{key}`) are limited per peer address by
  `pkarr_put_rate_limit`: one request every four seconds, two at once.
- **Lookups** (`GET /pkarr/{key}` and `/dns-query` by `GET` and `POST`) are limited by
  `lookup_rate_limit`: 50 a second, 100 at once, one quota per source shared by the three
  routes. With `simple`, a source is the IPv4 address of the connection, or the IPv6 /64 of it
  (an IPv4 address that arrives IPv6-mapped counts as IPv4). With `smart` the client address is
  read from the forwarding headers a reverse proxy sets (`X-Forwarded-For`, `X-Real-IP`,
  `Forwarded`) before it is mapped to its source: use it only behind a proxy that replaces
  those headers, because a client can send any value in them. A refused lookup is answered `429`
  and counted in `lookup_rate_limited`. Requests no route answers spend neither quota. DNS over
  UDP and TCP is not limited by the server.
- **Timestamps.** A packet stays in the store for `zone_store.eviction` counted from the time it
  is signed with. A publication signed more than 10 minutes ahead of the server's clock is
  refused with `400` and counted in `pkarr_publish_timestamp_ahead`; the server's clock has to
  be right for this to hold.
  - The refusal keeps a packet dated far ahead out of the store, and a later publication with a
    correct date replaces the record.
  - The publisher in iroh 1.2 does not read the body of the `400`, so its device is not told.
    The publisher's timestamp never goes back inside a process: a process whose clock ran fast
    keeps signing ahead of the server until real time catches up, or until it restarts with a
    correct clock. Its last accepted record expires after the retention period meanwhile.
  - A packet stored before the limit existed, or while the server's clock was set back, stays
    until its own date has passed. Until then the store ignores that endpoint's publications
    with an earlier date, which is every correct one (they answer `204` and change nothing), and
    the first publication dated after it replaces the packet. An endpoint that no longer
    publishes leaves it until its date plus the retention period. No cleanup removes such
    packets.
- **Eviction** removes a packet from the store and, when the store's writer does, from the zone
  cache. Once an eviction is done, DNS no longer answers the record from the store or the cache,
  and a lookup that read the packet before the eviction cannot put it back in the cache. A lookup
  that was already running can still answer with it once. With the mainline fallback on, DNS can
  answer the record from the DHT and cache it for 300 seconds, while `GET /pkarr/{key}` reads
  only the store and reports it absent.

`GET /healthz` reports `git_hash`: the revision in the `KR_FORK_REV` environment variable when
the server was built, and `unknown` when it was built without one.

# License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
