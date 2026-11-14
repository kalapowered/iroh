# KalaReach fork of iroh

This is KalaReach's fork of [`n0-computer/iroh`](https://github.com/n0-computer/iroh). Two
services build from it, and each pins a commit of the `kalareach` branch:

- the relay (`iroh-relay`, with a forwarding hook upstream does not have and an
  address-discovery listener with DATAGRAM frames turned off), and
- the discovery server (`iroh-dns-server`, with the fixes listed below).

The client links the published `iroh` crate, not this fork.

The deployments pin commits on `kalareach`, and the two pins move independently. History on the
branch is never rewritten and never force-pushed: a rewrite would orphan a commit a running
service was built from.

## Upstream base

| | |
| --- | --- |
| Tag | `v1.2.0` |
| Commit | `17c0612f80f78f5288e97b818b1360ae6ea0a51a` |
| `iroh`, `iroh-relay`, `iroh-dns-server`, `iroh-base` | 1.2.0 |
| `iroh-dns` | 1.3.0 |

The web repository records the same commit as `IROH_UPSTREAM_BASE_REV` in
`infra/relay/deployment.env` and `infra/discovery/deployment.env`. It moves when an upstream
release is merged, and only then.

## What the fork carries

Every patch is listed with the tests that prove it. A merge that drops a patch because upstream
replaced it removes the patch's tests with it, and only then.

### Relay: a forwarding hook (`iroh-relay`)

A `ForwardPolicy` an embedder installs decides each relayed payload at the two boundaries where
it is read from the sender and written to the receiver, and is told what became of every payload
it admitted. Upstream's admission callout decides whether a connection is accepted, and nothing
about the payloads that follow. The default policy, `ForwardAll`, forwards everything.

Tests, in `iroh-relay/src/server/clients.rs`, module `forwarding_policy_tests`:
`a_payload_with_nowhere_to_go_is_settled_as_dropped`,
`a_delivered_payload_is_settled_once_as_committed` and
`a_payload_the_destination_refuses_is_settled_as_dropped`.

### Relay: an address-discovery listener with DATAGRAM frames turned off (`iroh-relay`)

The relay answers QUIC address discovery on a UDP port: a client connects, the listener tells it
which address it saw. The client keeps the connection open for later reports and closes it when
it no longer needs it. The listener reads nothing else from a client, yet
upstream leaves DATAGRAM frames on, so a client could send them into a queue that nothing ever
reads. The fork turns datagram reception off in the listener's transport configuration. The
listener no longer offers DATAGRAM frames, and a connection that sends one is closed with a
protocol violation. Address discovery uses no DATAGRAM frame, so clients of 1.2.0 and 1.4.1 are not
affected.

Tests, in `iroh-relay/src/quic.rs`, module `tests`:
`the_listener_reports_the_address_and_offers_no_datagram_support` and
`a_datagram_the_listener_never_offered_ends_the_connection`.

### Discovery server (`iroh-dns-server`)

| Change | Why | Tests, in `iroh-dns-server/src` |
| --- | --- | --- |
| The packet store's writer tells the zone cache about every packet it replaces or removes. | Eviction removed a packet from the store and left it in the cache, so DNS answered with a record `GET /pkarr/{key}` already reported absent. | `store::tests::an_evicted_record_is_not_answered_from_the_cache`, `store::tests::evicting_one_endpoint_leaves_another_endpoints_zone_cached`, `store::tests::a_record_that_has_not_expired_stays_cached_through_an_eviction_pass`, `store::tests::a_publication_the_store_applied_reaches_the_cache_without_its_caller`, `store::tests::a_cache_left_in_doubt_by_a_panic_starts_over_and_counts_a_change_for_every_key`, `store::signed_packets::tests::the_writer_reports_each_change_it_applies_and_no_other`, `store::signed_packets::tests::an_eviction_is_reported_while_its_transaction_is_still_open`, `store::signed_packets::tests::a_packet_that_has_not_expired_is_not_reported_by_a_check` |
| A lookup caches what it read from the store only if no change to that key's packet happened since it started. | A lookup that overlapped a publication put the older packet back in the cache. | `store::tests::a_lookup_that_overlaps_a_publication_cannot_restore_the_older_packet`, `store::tests::a_lookup_that_overlaps_an_eviction_cannot_restore_the_evicted_packet`, `store::tests::a_lookup_with_no_overlap_caches_the_packet_it_read`, `store::tests::a_lookup_never_changes_the_packet_store`, `store::tests::a_dht_zone_is_not_cached_if_the_stored_packet_changed_during_the_lookup` |
| `lookup_rate_limit`: one quota per source network (an IPv4 address, or an IPv6 /64) for `GET /pkarr/{key}` and `/dns-query` by `GET` and `POST`; 50 a second, 100 at once. | Only `PUT /pkarr` had a request limit. | `http::tests::rate_limits::*`, `http::rate_limiting::tests::*`, `config::tests::*` |
| A publication signed more than ten minutes ahead of the server's clock is refused with `400`. | Eviction counts from the signed time, so a packet signed in the future stayed until its signed date plus the retention period. | `http::tests::publication::*`, `store::tests::a_timestamp_exactly_at_the_allowed_margin_is_accepted_and_one_microsecond_more_is_not`, `store::tests::timestamps_in_the_past_and_at_the_clock_are_accepted_and_the_largest_is_not`, `store::tests::a_refused_publication_changes_neither_the_store_nor_the_cache` |
| `/healthz` reports `git_hash` from `KR_FORK_REV` at build time. | The stock build and this one answered alike. | `http::tests::health::*` |
| Connections are bounded. A connection with no request in progress for 30 seconds is closed, counted from the end of its handshake or of its last request: one that sends nothing, an HTTP/2 connection with no request open whatever its peer sends, an idle keep-alive connection. A client keeps a connection by sending a request before each idle deadline. After its handshake, a connection reads at most 24,576 bytes (three times the head allowance of 8,192) between two request starts, and before its first, whatever requests are in progress; on the HTTPS listener these are the decrypted bytes. The count begins again when a request that is served starts, which is the first poll of the service for that request: for HTTP/2 the server has read the request's head by then and may have read more, the next heads and the body among it. A connection that reads more is closed, so that its client meets a connection that ends with no status. The figure is a threshold at which the connection is closed and not a ceiling on what the server holds: bytes read before a start can stay in what hyper has buffered for other requests, no read takes more than the one byte that crosses it, and the buffers of the socket and of the libraries lie outside it. An honest interval at the largest sizes holds two HTTP/2 heads of 8,192 bytes read ahead, the tail of the body before them and the first frames of the connection, about 20.6 kilobytes. A legal shape does not fit: two POSTs at once, each with a head near 8,191 bytes and a body of 4,096, come to about 24.6 kilobytes, and their connection is closed though the other limits allow each request (a POST's head is a few hundred bytes in practice). HTTP/2 holds a header block as it arrives until its last frame, and `HEADERS` with five `CONTINUATION` frames of 16,384 bytes that do not end the block is not a stream, so the limits on streams and on the header list do not bound it; this bound does. Until the TLS acceptor returns, a connection may send at most 32,768 raw bytes, a figure of its own: the TLS library holds a handshake message that arrives in pieces, up to 64 KiB, until the message ends, and the time limit of the handshake alone would let each connection hold that. The count ends when the acceptor returns, not at the client's `Finished` message: the acceptor reads on until it has decrypted one application record, so the first bytes of a client's requests count here when they arrive in the flight of that message. The largest honest handshake measured, with post-quantum key shares, every cipher suite and five ALPN names, sent 2,035 bytes; the figure allows 4,096 for it, one full application record of 16,406 bytes and the rest of the acceptor's last read, which the library's buffer of 18,437 bytes bounds. A request has ten seconds from its headers until the server has made its answer, body included (`408` after); delivering the answer is not part of the ten seconds, and a connection whose answer is not taken is closed by the 30 seconds once it has no request in progress. The body of `PUT /pkarr/{key}` is at most 1,072 bytes, the largest signed packet less the public key, and the body of `POST /dns-query` at most 4,096 bytes, the most the UDP path reads; past that is `413`, and so is a `dns=` value of `GET /dns-query` longer than the base64url form of 4,096 bytes (5,462 characters). What an unfinished request may hold is set on both listeners: an HTTP/1 head is read into at most 8,192 bytes, the lowest value hyper takes (default 417,792), and a longer head is answered `431`; an HTTP/2 connection has at most 2 streams open (default 200), a header list under 8,192 bytes as HTTP/2 counts it (default 16,384; a list of 8,192 or more is answered `431`), which leaves about 2.3 kilobytes for the other fields beside a query of 4,096 bytes by `GET`, a large cookie among them, a window of 4,096 bytes for each stream's body, the largest body of any route (default 1 MiB), and a window of 65,535 bytes for the connection, the protocol's own start value (default 1 MiB). The HTTP and HTTPS listeners together hold at most 8,192 connections; a connection past that is closed at once, before its handshake, and its request is not queued, while the connections already held stay usable; each such refusal is counted in `dns_server_http_connections_refused_total`. The TLS handshake has at most 30 seconds (the manual and self-signed acceptors also keep their own 10 seconds) and the HTTP/1 header read has 30 seconds. The listen backlog is 1024 by default (`listen_backlog`). | Upstream bounded only the handshake and the HTTP/1 header read, and left open a connection that is silent after its handshake, an idle HTTP/2 connection, a body that stops arriving or is as large as 2 MiB, and the protocol allowances above, each of which a sender could hold for as long as it liked or at a cost of hundreds of kilobytes. | `http::idle::tests::*`, `http::tests::test_silent_connection_closed`, `http::tests::test_silent_tls_connection_closed`, `http::tests::test_http2_connection_with_no_request_closed`, `http::tests::test_http2_connection_with_a_request_open_is_held_until_it_ends`, `http::tests::test_slow_request_body_gets_408`, `http::tests::test_body_limits`, `http::tests::test_http1_head_limit`, `http::tests::test_http2_stream_limit`, `http::tests::test_http2_header_list_limit`, `http::tests::test_http2_stream_window`, `http::tests::test_http2_connection_window_is_not_raised`, `http::tests::test_http2_unfinished_header_block_closes_the_connection`, `http::tests::test_http2_largest_requests_are_answered_one_after_another_and_at_once`, `http::tests::test_http1_largest_requests_are_answered_on_one_connection`, `http::tests::test_connections_past_the_most_are_closed_at_once`, `http::tests::test_connection_cap_is_one_count_over_both_listeners`, `http::tests::test_tls_handshake_past_the_bound_is_closed`, `http::tests::test_a_first_batch_with_the_last_handshake_message_is_answered`, `http::tests::test_the_most_connections_is_the_measured_figure`, `http::tests::test_read_bound_is_exact_over_http_and_tls`, `http::tests::test_a_close_by_either_bound_gives_the_place_back`, `http::tls::tests::a_handshake_may_send_the_bound_and_no_more`; upstream's `http::tests::test_idle_connection_closed`, `http::tests::test_listen_backlog` (Linux only) and `http::tls::tests::test_handshake_timeout`, which arrive with the fork's copy of upstream's two commits and which a later merge of upstream keeps as its own |

These bounds do not stop a party that has many networks and keeps sending: it can hold the server's
connections open by sending a request on each before its idle deadline, and its requests are limited to ten
seconds and a few kilobytes each. What the host sets for that party is the firewall's caps on connections for
each source address and each source network, and the service's descriptor limit. The cap of 8,192
bounds the number of connections the server holds.

What held connections cost was measured on the build box (AMD EPYC 7502P, Linux), on a release build with one TLS listener on loopback and the rate limits off, with a descriptor limit of 65,536, inside a control group with the service's limit of 2 GiB (as `MemoryHigh` and `MemoryMax`, no swap). The figure is the peak of the group's own memory (`memory.peak`, which counts the sockets' kernel memory and the empty server's 9 MiB), for the number of connections the column names:

| Each of the connections | 16,384 connections | 8,192 connections (the cap) |
| --- | --- | --- |
| sends a request every 20 seconds and nothing else | 425 MiB | 227 MiB |
| holds an unfinished HTTP/1 head of 8,191 bytes | 576 MiB | 295 MiB |
| holds 2 HTTP/2 streams open, each with a header list of 8,191 bytes and 4,090 body bytes | 948 MiB | 500 MiB |
| sends `HEADERS` and five `CONTINUATION` frames of 16,384 bytes that do not end the block | 497 MiB; the bound on bytes between request starts then closed every connection | 267 MiB; closed likewise |
| sends the 2 streams of the third row and at once a block of 20,000 bytes that does not end | 563 MiB; the bound closed 14,791 of the 16,384 connections | not measured |
| sends the 2 streams, the second 2.5 seconds after the first, and 2.5 seconds later a block of 20,000 bytes that does not end, so that the bytes read since the second request started stay under the bound | 1,642 MiB; no connection was closed | 857 MiB; no connection was closed |
| sends the start of a TLS `ClientHello` that declares 65,535 bytes, 65,472 raw bytes in four records, with no bound on the handshake | 1,085 MiB; the 10 seconds of the handshake then closed every connection | not measured |
| sends the same start, 32,767 raw bytes in two records, one byte under the bound of 32,768 on the handshake | not measured | 437 MiB; the 10 seconds of the handshake then closed every connection |

The sixth row is the heaviest shape of this table: the bound on bytes between request starts lets a connection hold two open streams and a block that stays under the bound. At 16,384 connections it took 102.1 KiB for each connection. The cap of 8,192 was taken from that cost: 8,192 connections at 102.1 KiB, with the empty server's 9 MiB, come to 826 MiB, and 8,192 connections in that shape held 857 MiB at the peak of the group, 106 KiB each. No process was killed in these runs, and the group's `oom` and `oom_kill` stayed at 0.

### Memory budget

The service runs in a unit with a memory limit of 2 GiB and no swap. The limit counts the anonymous memory of the process, the kernel's memory for its sockets and the file cache, which the kernel fills and reclaims. Each figure below bounds one part. They were measured on the build box (AMD EPYC 7502P, Linux 7.0, 64 threads), on a release build with one TLS listener on loopback and the rate limits off, inside a control group with the unit's limit (`MemoryHigh` and `MemoryMax` of 2 GiB, `MemorySwapMax` of 0).

| What | Figure | What it bounds, and what was measured |
| --- | --- | --- |
| Zone cache | 131,072 zones | The zones that answer DNS without a read of the packet store; a miss costs one read. A zone held 3.2 kB at capacity with `MALLOC_ARENA_MAX=2` and 4.9 kB with the default arenas. |
| Cache of DHT zones | 16,384 zones | The same for zones that come from the DHT. |
| Page cache of the packet database | 256 MiB (the library's default is 1 GiB) | What the database keeps of its pages. The database part of the process levelled off at about 290 MiB above the empty server over 400,000 stored zones; nothing else grows with each stored zone. |
| Connections | 8,192 | See the table of shapes above: 857 MiB at the peak of the shape of its sixth row. |
| Socket buffers | 4 KiB for receive, 8 KiB for send, on each accepted socket of the HTTP and HTTPS listeners | The kernel's queues for a client that sends and does not read, below. |
| Bytes a connection may read in its life | 64 KiB | What a connection may send in its life, so that nothing that a connection makes the server keep can grow with the connection's age. The rows are below. |

The allocator's setting belongs to the deployment: the unit sets `MALLOC_ARENA_MAX=2`, and the figures are those of a run with it. On the build box, which has 64 threads, 400,000 stored zones held 948 MiB of anonymous memory with the allocator's default setting and 723 MiB with 2 arenas; no other host was measured.

What the kernel's socket buffers cost was measured with 8,192 connections, one TLS listener, and clients that send and do not read. The group's peak, with the buffers fixed:

| Each of the connections | Group peak |
| --- | --- |
| sends `GET /pkarr/{key}` requests one after another (about 90 bytes each, an answer of about 1,200 bytes) over HTTP/1 and reads no answer | 729 MiB (407 MiB of socket memory); no process killed |
| opens HTTP/2 streams one after another, each a `GET` that ends, and reads no answer | 586 MiB |
| the same, then a `PING` and `PING` frames without end | 470 MiB; the bound on bytes between request starts closed every connection |

On the build box a connection starts with a send buffer of 2.5 MiB and a receive buffer that tunes itself up to 32 MiB. A buffer set on the listening socket before `listen` is the accepted socket's and the kernel does not tune it; the kernel keeps twice the figure. 4 KiB is the least at which the largest `ClientHello` measured, 2,035 bytes, arrives in one flight with a margin of 2 (a write of 20,000 bytes to a server that did not read arrived 4,308 bytes at 4 KiB and 2,048 at 2 KiB, with a client segment size of 1,448); 8 KiB is the least at which one send takes a handshake flight of about 5 kB (9,412 bytes at 8 KiB, 5,068 at 4 KiB). A larger request is read as the server takes it in, and the largest honest request, a head of 8,192 bytes with a body of 4,096, is answered. The send queue holds, beside the buffer, one buffer of the kernel's own of up to 64 KiB, so a connection holds about 50 kB of socket memory in the first row, and the buffer sizes do not bound that.

Before the budget of a connection's life, the proof was a run of the server in the group with 8,064 held connections, 6,016 in the shape of the sixth row above and 2,048 that pipeline requests and read no answer, a store filled to 400,000 zones, each looked up once as it was published, and 150,000 lookups of the first zones while the shapes are held. The peak of anonymous, kernel and socket memory, taken from the group's own figures every two seconds, with `MALLOC_ARENA_MAX=2`: 1,563 MiB for the ordinary packet and 1,423 MiB for the largest (1,072 bytes), against the limit of 2,048 MiB less 15 per cent, 1,741 MiB; no process was killed, `oom` and `oom_kill` stayed at 0, and DNS answered on the server's own port throughout. The same run with the default arenas peaked at 1,855 MiB. The group's total reaches 2,048 MiB in every run, because the kernel's file cache fills it and is reclaimed.

A connection that has read more than 64 KiB takes no further request, by these rules:

- The requests in progress at the moment the figure is passed are the last ones served. If none is in progress, the last one served is the first request that starts. The bytes that carried the figure make no difference: they may be the head of a request, its body or other bytes.
- A request that starts after those is refused, and its handler does not run. Over HTTP/2 its stream is reset as refused, which tells the client that the request was not processed and may be sent again; over HTTP/1 the answer to the last request served says that the connection closes. A connection that refuses a request with no other in progress ends once the reset is written, so a client that sends the request again opens a new connection. One with other requests in progress stands until they have ended.
- A connection that takes no further request stands for 1 second at most when it has no request in progress, in place of the idle bound's 30. The second is not zero, because an answer is written after the request that made it has ended. A connection that passed the figure with no request in progress keeps the ordinary times until its next request starts, since a head may be in transit.
- So a connection ends at most 41 seconds after the figure is passed (the idle bound of 30 seconds, the request deadline of 10 seconds and the 1 second), and gives back its place under the cap. It reads at most 49,154 bytes after the figure, twice the 24,577 bytes that the bound between two request starts allows, which no read takes past.

A client that keeps one connection for many requests meets the refusal after about 64 KiB of requests (over HTTP/2 an ordinary request is some tens of bytes), and its client library sends the request again on a new connection. The cases `test_http1_ordinary_client_is_served_across_the_lifetime_budget` and `test_http2_ordinary_client_is_served_across_the_lifetime_budget` hold that with `reqwest`, the client library of the server's own tests: no caller sees an error, no request runs twice, and each refused request is answered on a new connection. Over HTTP/2, a client that has two requests in progress when the figure is passed has the later one refused while the first is answered whole, and its retry meets the same connection until the first has ended; a client library that retries a refusal only twice can return an error for that request.

The figure was taken from three measured rows, for the heaviest shape measured, which is heavier than the sixth row's. The proof's mix is 8,064 held connections: 2,048 that pipeline requests and read no answer, 1,024 in the heaviest shape measured and 4,992 in the shape of the sixth row above, with the store at 400,000 zones and 150,000 lookups. The rows were measured on the build box, in the group, with `MALLOC_ARENA_MAX=2`:

| The budget | 1,024 connections in the heaviest shape measured, group peak | 8,192 connections in it, group peak | The proof's mix, peak of anonymous, kernel and socket memory | Headroom to the limit |
| --- | --- | --- | --- | --- |
| 32 KiB | 99 MiB | 372 MiB | 1,458 MiB | 29% |
| 48 KiB | 132 MiB | 378 MiB | 1,476 MiB | 28% |
| 64 KiB | 163 MiB | 425 MiB | 1,483 MiB | 28% |

All three keep the 15 per cent that the proof asks for (1,741 MiB). The figure is 64 KiB, the largest of the three, which keeps the most requests for each connection.

The table that the server keeps for the headers of its answers is capped at 4 KiB by the locked version of its HTTP/2 library, and the case `test_http2_answers_keep_the_header_table_at_4_kib` holds that. With 2,048 connections, one request a second on each for 3,000 seconds and a peer that announces a table of 1 MiB, the group's anonymous memory stayed between 92 and 99 MiB on the build box, with `MALLOC_ARENA_MAX=2`.

The rate limiter keeps one entry for each source address (an IPv6 address by its /64) that sent a request in the last minutes, with no count of entries; it is cleaned every 60 seconds. An entry is a 17-byte address and an 8-byte state in a 32-byte slot of the table, with one control byte, which the table keeps at most 7/8 full and doubles when full: between 38 and 75 bytes (by the sizes of the types, not measured). The host's firewall lets one /24 open 100 connections a second, so with 120 seconds as the longest that an entry stays, one /24 adds at most 12,000 entries, about 0.9 MB, and 1,000 such networks about 0.9 GB. The limit is not in the server, which has no count of entries.

The server does not count connections of port 53 over TCP. The DNS library ends one that sends nothing after 1 second. A deployment bounds their number at its firewall; ours allows 1,024 at once, beside its limits for one address and one network.

Not bounded by these figures: the settings of the host's kernel, whose limits on TCP memory and on buffer sizes were larger on the build box than a host of 3.9 GB has.

A deployment builds with `KR_FORK_REV` set to the commit it pins, and compares `/healthz` with
it.

## Fixing a vulnerability

The daily check reads the lock files that build the two deployed binaries: the fork's `Cargo.lock`
at the discovery pin, and `infra/relay/kr-relay/Cargo.lock` in the web repository for the relay. An
advisory applies when the version a lock file holds is in its affected range.

### An upstream release of an iroh crate

A release that fixes a vulnerability in `iroh`, `iroh-relay`, `iroh-dns-server`, `iroh-dns` or
`iroh-base` reaches the fork by a **merge**, never a rebase.

1. Fetch the upstream tag. Create `merge/upstream-<version>` from `kalareach` and merge the tag
   into it. Resolve conflicts by keeping every patch listed
   above. Update the base table above on this branch.
2. Run the suites of the two services: `cargo test --locked -p iroh-relay --features server` and
   `cargo test --locked -p iroh-dns-server`. Every test named above must still exist and pass.
   A patch upstream has replaced is removed together with its tests and its row.
3. Before rollout, in the web repository, run the relay wrapper's tests (`cargo test` in
   `infra/relay/kr-relay`, with its lock file at the new fork commit as step 5 says) and the relay
   end-to-end suite (`scripts/e2e-relay.sh`), with the merged builds against every client version
   the signed release matrix supports. `scripts/e2e-discovery.sh` talks to the live discovery
   service, so it runs after the discovery deploy of step 5, as the first end-to-end proof of the
   new build, against the same client versions. A network tier is compatible with the installed
   clients before a client that needs the new behaviour ships.
4. Fast-forward `kalareach` to the merge branch.
5. In one change to the web repository, move both pins to the new tip:
   - discovery: `IROH_DNS_SERVER_FORK_REV` in `infra/discovery/deployment.env`;
   - relay: `IROH_RELAY_FORK_REV` in `infra/relay/deployment.env`, the two `rev =` lines naming the
     fork in `infra/relay/kr-relay/Cargo.toml`, and `infra/relay/kr-relay/Cargo.lock` regenerated
     to hold that commit (the relay's installer refuses a lock file that does not);
   - `IROH_UPSTREAM_BASE_REV` in both `deployment.env` files, to the merged upstream commit.

   Then deploy both services.

A fix that a merge cannot deliver in time, because the release also carries changes that need
review, may be cherry-picked onto a branch from `kalareach` instead. A cherry-pick leaves the
crate versions where they were, so the daily check keeps reporting the advisory until it is
acknowledged in `infra/scripts/upstream-security.acknowledgements.json`, with a reason that names
the fork commit that carries the fix. The merge follows when the review is done.

The client links the published `iroh` crate, and through it `iroh-relay`, `iroh-base` and
`iroh-dns`. When an advisory names one of those, the check says that if the advisory is in code the
client uses, the fix is also a dependency step in the client's own repository, scheduled through
the release matrix.

### A vulnerability in another package a lock file holds

A package such as `hickory-server`, `rustls`, `hyper` or `h2` is updated in the lock file that holds
it, to the patched version:

- In the fork's `Cargo.lock`, for the discovery server: `cargo update -p <package> --precise
  <version>` on a branch from `kalareach`, the suites of step 2, a fast-forward, then the
  discovery pin of step 5, a discovery deploy and `scripts/e2e-discovery.sh` against the supported
  client versions. The relay is untouched.
- In `infra/relay/kr-relay/Cargo.lock`, for the relay: the same `cargo update` in that directory,
  in the web repository. It needs no fork commit and no fast-forward. Run the wrapper's tests and
  `scripts/e2e-relay.sh` of step 3, then deploy the relay.

### How fast

| Advisory that applies to a locked package | Fixed within | Deployed |
| --- | --- | --- |
| High or critical severity, or no severity given | 3 days of publication | the day the fix lands |
| Any other vulnerability | 14 days of publication | with the fix |

An upstream release without an advisory sets no deadline. It waits for the next scheduled
dependency step, and the check does not fail on it. Unmaintained, unsound and yanked notices are
reported and do not fail the check.

### How a lapse is noticed

`infra/scripts/upstream-security.mjs` in the web repository runs daily as the
`upstream-security` workflow, and on demand. It checks every package in the two lock files against
the RustSec database with `cargo audit`, and the five crates above against GitHub's published
advisories. Both are needed: `cargo audit` matches only packages from a registry, and the fork's
crates are path packages in the fork's own lock file and git packages in the relay's, so it never
reports one for them, whatever RustSec lists. (The relay's lock file also holds registry copies of
some of them, pulled in by a dev-dependency on the published `iroh`, which `cargo audit` does check;
the relay binary runs the git copies.) GitHub imports the RustSec advisories too, and its
review of an advisory upstream has published can take days; the deadline counts from publication.
The check exits `1`, naming each advisory, its patched version and its deadline, when an advisory
applies and is not acknowledged, and `2` when a source cannot be read, after printing what it could
read. A failed run is the notice.
