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
  routes. An IPv4 client is its own source and an IPv6 client is its /64. A refused lookup is
  answered `429` and counted in `lookup_rate_limited`. DNS over UDP and TCP is not limited by
  the server.
- **Timestamps.** A packet stays in the store for `zone_store.eviction` counted from the time it
  is signed with. A publication signed more than 10 minutes ahead of the server's clock is
  refused with `400` and counted in `pkarr_publish_timestamp_ahead`. A packet stored before
  that limit existed, or while the server's clock was set back, stays until its own date has
  passed and the retention period after it.
- **Eviction** removes a packet from the store and from the zone cache, so DNS never answers
  with a record that `GET /pkarr/{key}` reports absent.

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
