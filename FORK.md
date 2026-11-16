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
| Connections are bounded. A connection with no request in progress for 30 seconds is closed, counted from the end of its handshake or of its last request: one that sends nothing, an HTTP/2 connection with no request open whatever its peer sends, an idle keep-alive connection. A client keeps a connection by sending a request before each idle deadline. After its handshake, a connection reads at most 24,576 bytes (three times the head allowance of 8,192) between two request starts, and before its first, whatever requests are in progress; on the HTTPS listener these are the decrypted bytes. The count begins again when a request that is served starts, which is the first poll of the service for that request: for HTTP/2 the server has read the request's head by then and may have read more, the next heads and the body among it. A connection that reads more is closed, so that its client meets a connection that ends with no status. The figure is a threshold at which the connection is closed and not a ceiling on what the server holds: bytes read before a start can stay in what hyper has buffered for other requests, no read takes more than the one byte that crosses it, and the buffers of the socket and of the libraries lie outside it. An honest interval at the largest sizes comes to about 20.6 kilobytes. The largest requests that the other limits allow, two at once, come to about 24.6 kilobytes, and their connection is closed though the other limits allow each request (a POST's head is a few hundred bytes in practice). The bound also covers what the limits on streams and on the header list do not count: request data that has been read and has not yet become a request. Until the TLS acceptor returns, a connection may send at most 32,768 raw bytes, a figure of its own: the TLS library holds a handshake message that arrives in pieces, up to 64 KiB, until the message ends, and the time limit of the handshake alone would let each connection hold that. The count ends when the acceptor returns, not at the client's `Finished` message: the acceptor reads on until it has decrypted one application record, so the first bytes of a client's requests count here when they arrive in the flight of that message. The largest honest handshake measured, with post-quantum key shares, every cipher suite and five ALPN names, sent 2,035 bytes; the figure allows 4,096 for it, one full application record of 16,406 bytes and the rest of the acceptor's last read, which the library's buffer of 18,437 bytes bounds. A request has ten seconds from its headers until the server has made its answer, body included (`408` after); delivering the answer is not part of the ten seconds, and a connection whose answer is not taken is closed by the 30 seconds once it has no request in progress. The body of `PUT /pkarr/{key}` is at most 1,072 bytes, the largest signed packet less the public key, and the body of `POST /dns-query` at most 4,096 bytes, the most the UDP path reads; past that is `413`, and so is a `dns=` value of `GET /dns-query` longer than the base64url form of 4,096 bytes (5,462 characters). What an unfinished request may hold is set on both listeners: an HTTP/1 head is read into at most 8,192 bytes, the lowest value hyper takes (default 417,792), and a longer head is answered `431`; an HTTP/2 connection has at most 2 streams open (default 200), a header list under 8,192 bytes as HTTP/2 counts it (default 16,384; a list of 8,192 or more is answered `431`), which leaves about 2.3 kilobytes for the other fields beside a query of 4,096 bytes by `GET`, a large cookie among them, a window of 4,096 bytes for each stream's body, the largest body of any route (default 1 MiB), and a window of 65,535 bytes for the connection, the protocol's own start value (default 1 MiB). The HTTP and HTTPS listeners together hold at most 8,192 connections; a connection past that is closed at once, before its handshake, and its request is not queued, while the connections already held stay usable; each such refusal is counted in `dns_server_http_connections_refused_total`. The TLS handshake has at most 30 seconds (the manual and self-signed acceptors also keep their own 10 seconds) and the HTTP/1 header read has 30 seconds. The listen backlog is 1024 by default (`listen_backlog`). A connection that has read 64 KiB in its life is shut down gracefully and is ended within 20 seconds of that call; the rules and their limits are under "Memory budget" below. Each listener runs a serve loop of the fork's own: the handshake and the connection cap run inside the connection's task, so a stalled handshake holds nothing but its own task, and the connections end with the loop. | Upstream bounded only the handshake and the HTTP/1 header read, and left open a connection that is silent after its handshake, an idle HTTP/2 connection, a body that stops arriving or is as large as 2 MiB, and the protocol allowances above, each of which a sender could hold for as long as it liked. | `http::idle::tests::*`, `http::serve::tests::*`, `http::tests::test_silent_connection_closed`, `http::tests::test_silent_tls_connection_closed`, `http::tests::test_http2_connection_with_no_request_closed`, `http::tests::test_http2_connection_with_a_request_open_is_held_until_it_ends`, `http::tests::test_slow_request_body_gets_408`, `http::tests::test_body_limits`, `http::tests::test_http1_head_limit`, `http::tests::test_http2_stream_limit`, `http::tests::test_http2_header_list_limit`, `http::tests::test_http2_stream_window`, `http::tests::test_http2_connection_window_is_not_raised`, `http::tests::test_http2_unfinished_request_head_closes_the_connection`, `http::tests::test_http2_largest_requests_are_answered_one_after_another_and_at_once`, `http::tests::test_http1_largest_requests_are_answered_on_one_connection`, `http::tests::test_connections_past_the_most_are_closed_at_once`, `http::tests::test_connection_cap_is_one_count_over_both_listeners`, `http::tests::test_tls_handshake_past_the_bound_is_closed`, `http::tests::test_a_first_batch_with_the_last_handshake_message_is_answered`, `http::tests::test_the_most_connections_is_the_measured_figure`, `http::tests::test_read_bound_is_exact_over_http_and_tls`, `http::tests::test_a_close_by_either_bound_gives_the_place_back`, `http::tls::tests::a_handshake_may_send_the_bound_and_no_more`, `http::tests::test_http1_connection_is_answered_up_to_its_lifetime_budget`, `http::tests::test_http2_answer_blocked_by_the_window_is_delivered_whole_in_the_drain`, `http::tests::test_http2_head_in_transit_when_the_figure_is_passed_is_answered`, `http::tests::test_http2_shutdown_frames_come_in_order_and_no_stream_is_reset`, `http::tests::test_http2_peer_with_unread_input_at_the_close_reads_the_whole_answer`, `http::tests::test_http2_stream_after_the_cutoff_runs_no_handler_and_gets_no_frame`, `http::tests::test_http2_two_streams_in_progress_at_the_figure_are_both_answered`, `http::tests::test_http2_request_after_the_figure_starts_the_shutdown_while_it_is_held`, `http::tests::test_http2_answer_that_the_window_blocks_ends_with_the_drain_time`, `http::tests::test_http2_request_accepted_late_in_the_drain_is_cut_at_the_drain_time`, `http::tests::test_http2_ping_that_is_never_acknowledged_ends_with_the_drain_time`, `http::tests::test_http2_head_that_stays_in_transit_ends_with_the_drain_time`, `http::tests::test_http2_bytes_after_the_first_goaway_end_the_connection_at_the_stop`, `http::tests::test_http1_request_in_progress_at_the_figure_is_answered_with_close`, `http::tests::test_http1_head_in_transit_when_the_figure_is_passed_is_answered`, `http::tests::test_http2_ordinary_clients_are_served_across_the_figure`, `http::tests::test_http2_requests_waiting_on_one_client_meet_at_most_one_error_at_the_figure`, `http::tests::test_http2_over_tls_ordinary_clients_are_served_across_the_figure`, `http::tests::test_http1_ordinary_clients_are_served_across_the_figure`, `http::tests::test_a_stalled_handshake_does_not_delay_another_connection`, `http::tests::test_shutdown_ends_standing_connections`; upstream's `http::tests::test_idle_connection_closed`, `http::tests::test_listen_backlog` (Linux only) and `http::tls::tests::test_handshake_timeout`, which arrive with the fork's copy of upstream's two commits and which a later merge of upstream keeps as its own |

These bounds do not stop a party that has many networks and keeps sending: it can hold the server's
connections open by sending a request on each before its idle deadline, and its requests are limited to ten
seconds and a few kilobytes each. What the host sets for that party is the firewall's caps on connections for
each source address and each source network, and the service's descriptor limit. The cap of 8,192
bounds the number of connections the server holds.

What held connections cost was measured on the build box (AMD EPYC 7502P, Linux), on a release build with one TLS listener on loopback and the rate limits off, with a descriptor limit of 65,536, inside a control group with the service's limit of 2 GiB (as `MemoryHigh` and `MemoryMax`, no swap). The figure is the peak of the group's own memory (`memory.peak`, which counts the sockets' kernel memory and the empty server's 9 MiB), for the number of connections the column names. The shapes are numbered in the order in which they were measured:

| Shape of each connection | 16,384 connections | 8,192 connections (the cap) |
| --- | --- | --- |
| Shape 1 | 425 MiB | 227 MiB |
| Shape 2 | 576 MiB | 295 MiB |
| Shape 3 | 948 MiB | 500 MiB |
| Shape 4 | 497 MiB; the bound on bytes between request starts then closed every connection | 267 MiB; closed likewise |
| Shape 5 | 563 MiB; the bound closed 14,791 of the 16,384 connections | not measured |
| Shape 6 | 1,642 MiB; no connection was closed | 857 MiB; no connection was closed |
| Shape 7 | not measured | 437 MiB; the 10 seconds of the handshake then closed every connection |

Shape 6 is the heaviest shape measured, and the table does not cover every shape: the rows of the memory budget below are for another one. In shape 6 the bound on bytes between request starts is in force, and at 16,384 connections it took 102.1 KiB for each connection. The cap of 8,192 was taken from that cost: 8,192 connections at 102.1 KiB, with the empty server's 9 MiB, come to 826 MiB, and 8,192 connections in that shape held 857 MiB at the peak of the group, 106 KiB each. No process was killed in these runs, and the group's `oom` and `oom_kill` stayed at 0.

### Memory budget

The service runs in a unit with a memory limit of 2 GiB and no swap. The limit counts the anonymous memory of the process, the kernel's memory for its sockets and the file cache, which the kernel fills and reclaims. Each figure below bounds one part. They were measured on the build box (AMD EPYC 7502P, Linux 7.0, 64 threads), on a release build with one TLS listener on loopback and the rate limits off, inside a control group with the unit's limit (`MemoryHigh` and `MemoryMax` of 2 GiB, `MemorySwapMax` of 0).

| What | Figure | What it bounds, and what was measured |
| --- | --- | --- |
| Zone cache | 131,072 zones | The zones that answer DNS without a read of the packet store; a miss costs one read. A zone held 3.2 kB at capacity with `MALLOC_ARENA_MAX=2` and 4.9 kB with the default arenas. |
| Cache of DHT zones | 16,384 zones | The same for zones that come from the DHT. |
| Page cache of the packet database | 256 MiB (the library's default is 1 GiB) | What the database keeps of its pages. The database part of the process levelled off at about 290 MiB above the empty server over 400,000 stored zones; nothing else grows with each stored zone. |
| Connections | 8,192 | See the table of shapes above: 857 MiB at the peak of shape 6. |
| Socket buffers | 4 KiB for receive, 8 KiB for send, on each accepted socket of the HTTP and HTTPS listeners | The kernel's queues for a client that sends and does not read, below. |
| Bytes a connection reads before its graceful shutdown | 64 KiB | The figure at which the drain begins, not the whole allowance of a connection's life, which ends at its 90,113th byte (the rules below). With the 24,575 bytes that may follow it, it bounds what a connection may send in its life, so that nothing that a connection makes the server keep can grow with the connection's age. The rows are below. |

The allocator's setting belongs to the deployment: the unit sets `MALLOC_ARENA_MAX=2`, and the figures are those of a run with it. On the build box, which has 64 threads, 400,000 stored zones held 948 MiB of anonymous memory with the allocator's default setting and 723 MiB with 2 arenas; no other host was measured.

What the kernel's socket buffers cost was measured with 8,192 connections, one TLS listener, and clients that send and do not read. The group's peak, with the buffers fixed:

| Shape of each connection | Group peak |
| --- | --- |
| Shape A | 729 MiB (407 MiB of socket memory); no process killed |
| Shape B | 586 MiB |
| Shape C | 470 MiB; the bound on bytes between request starts closed every connection |

On the build box a connection starts with a send buffer of 2.5 MiB and a receive buffer that tunes itself up to 32 MiB. A buffer set on the listening socket before `listen` is the accepted socket's and the kernel does not tune it; the kernel keeps twice the figure. 4 KiB is the least at which the largest `ClientHello` measured, 2,035 bytes, arrives in one flight with a margin of 2 (a write of 20,000 bytes to a server that did not read arrived 4,308 bytes at 4 KiB and 2,048 at 2 KiB, with a client segment size of 1,448); 8 KiB is the least at which one send takes a handshake flight of about 5 kB (9,412 bytes at 8 KiB, 5,068 at 4 KiB). A larger request is read as the server takes it in, and the largest honest request, a head of 8,192 bytes with a body of 4,096, is answered. The send queue holds, beside the buffer, one buffer of the kernel's own of up to 64 KiB, so a connection holds about 50 kB of socket memory in shape A. The buffer sizes do not bound that; the cap of 8,192 connections bounds the total, which was 407 MiB in shape A above.

A connection that has read more than 64 KiB is shut down gracefully, by these rules:

- When the figure is passed, the connection's own task calls the graceful shutdown of the HTTP library at the first moment a request is in progress: at the crossing if one is, otherwise when the next request starts. The requests in progress, and those that start before the client has read the shutdown, are served and their answers are sent; no request is refused. A request head that is in transit when the figure is passed, with no request in progress, is not cut: it completes under the ordinary times and is the first request after the figure. The bytes that carried the figure make no difference: they may be the head of a request, its body or other bytes.
- The library tells the client. Over HTTP/2 it sends a `GOAWAY`, a `PING`, and, once the client has acknowledged the `PING`, a second `GOAWAY` that names the last stream it accepted; a frame of a stream above that one is ignored and no handler runs for it. Over HTTP/1 the answer to a request says that the connection closes; the service adds that header itself, because the library closes a connection with no request in progress at once. The connection ends when its answers are out.
- The shutdown has 20 seconds from the call. A connection that is still open then is dropped, with no `close_notify`, and counted in `dns_server_http_connections_drain_timeouts_total`. The counter holds every connection that reached the 20 seconds, whatever the cause: an answer that the client holds back through its flow-control window or a slow link, a body or a handler that runs on, a request accepted late in the drain, a head that stays in transit, and a client that never acknowledges the `PING`, which leaves the connection standing until the timer. The stop on bytes below is not counted.
- The read that carries the figure ends at the byte that passes it, the 65,537th of the connection's life. The connection reads 24,575 bytes more, and its 90,113th byte ends it with no further notice. A request start does not begin this count again, and every byte that the wrapper reads counts, whatever it carries. On the HTTPS listener these are decrypted bytes.
- A connection that passed the figure with no request in progress stands under the idle bound of 30 seconds from its last request until a request starts, and then for 20 seconds from the call, so it ends at most 50 seconds after its last request ended, and gives back its place under the cap. With a request in progress at the crossing it ends within 20 seconds.

What the rules do not promise:

- A request that the service accepted and that is not finished within the 20 seconds is cut with its connection: an answer that the client's window or a slow link holds back, a body or a handler that runs on, a request accepted late in the drain with its body and its handler. Over HTTP/2 the library goes on accepting streams until the client has acknowledged the `PING`. The client meets a connection that ends with no `close_notify`. A `GOAWAY` is not a promise about the result of such a request: a replay that the protocol authorises is one thing, and an application's retry after an uncertain result is another, and it depends on whether the operation tolerates being repeated. The stop on bytes can leave an uncertain result in the same way.
- A request head that stays in transit for more than 20 seconds after the call, beside a request in progress, is cut with the connection, where the idle bound would have allowed 30.
- More than 24,575 bytes after the byte that passes the figure end the connection, whatever they carry.
- Two cuts are not new. An answer that the client's window blocks, and that is not delivered, ends at the idle bound of 30 seconds after its handler has returned. Over HTTP/1 a request that the client pipelined behind the closing answer is not answered.

A client that keeps one connection for many requests is told, after about 64 KiB of requests (over HTTP/2 an ordinary request is some tens of bytes), to continue on a new one. The cases `test_http1_ordinary_clients_are_served_across_the_figure`, `test_http2_ordinary_clients_are_served_across_the_figure` and `test_http2_over_tls_ordinary_clients_are_served_across_the_figure` run `reqwest`, the client library of the server's own tests: eight clients, each on a task of its own and so with a connection of its own, send 200 requests one at a time, each with a padded header of its own. The requests of one client cost more than twice what a connection may read in its life, so each client crosses the figure at least twice, and each case asserts that every caller got its answer with a whole body, that every request ran at least once and at most three times, that no request ran that no caller sent, that every client was served by at least three connections, and that the drain time cut none. The most is three because `reqwest` sends a request again at most twice; a failure names each request that ran more than once with the connections that carried its runs. The server runs one handler for each request that it receives, and a request above the final notice's number is not run; a client library that sends a request again after a shutdown notice makes a second request, which the server handles as any other. Every route of this server gives the same result for a request that arrives twice: a publication is a signed packet with its own time, and the store keeps the newest packet for a key, so a copy leaves the stored packet as it was; a lookup changes nothing in the store; the other routes answer fixed text. Only the request limits tell the two arrivals apart, since each counts against a quota. A client that has more requests waiting than a connection's 2 streams can get an error for a waiting request when the connection reaches its read figure, and it sends the request again. The case `test_http2_requests_waiting_on_one_client_meet_at_most_one_error_at_the_figure` runs eight tasks on one HTTP/2 client across the figure: every request gets its whole answer or fails with that one client error, a request sent again on the same client is answered, and no handler runs more often than its request was sent. The server's own client speaks HTTP/1 and reads the header that says the connection closes.

How often an ordinary client meets the figure depends on what a request costs the connection, the bytes that the server reads for it. Measured with `reqwest` and one request at a time, over HTTP/2 a plain `GET` costs about 20 bytes, so a connection served 3,239 requests before its shutdown, and 2,761 on the next; over HTTP/1 it costs about 100 bytes, and the connections served between 193 and 1,093 requests, 667 on average. A request with a padded header cost the HTTP/2 connection about 1,200 bytes and the HTTP/1 connection about 1,560, which is 54 and 42 requests before the shutdown.

The figure was taken from three measured rows, for a shape that these notes call the budget's shape. The proof's mix is 8,064 held connections: 2,048 that read no answer, 1,024 in the budget's shape and 4,992 in shape 6 above, with the store at 400,000 zones and 150,000 lookups. The proof asks that the mix peak at no more than the limit of 2,048 MiB less 15 per cent, 1,741 MiB. The three rows were measured on the build box, in the group, with `MALLOC_ARENA_MAX=2`, with an earlier build that closed a connection at its figure, and not with the build that these notes describe, which shuts a connection down gracefully:

| The budget | 1,024 connections in the budget's shape, group peak | 8,192 connections in it, group peak | The proof's mix, peak of anonymous, kernel and socket memory | Headroom to the limit |
| --- | --- | --- | --- | --- |
| 32 KiB | 99 MiB | 372 MiB | 1,458 MiB | 29% |
| 48 KiB | 132 MiB | 378 MiB | 1,476 MiB | 28% |
| 64 KiB | 163 MiB | 425 MiB | 1,483 MiB | 28% |

All three keep under 1,741 MiB. The figure is 64 KiB, the largest of the three, which keeps the most requests for each connection.

The build that these notes describe was measured on the same box, in the same group and with `MALLOC_ARENA_MAX=2`. The proof's mix, with 1,024 connections in the budget's shape, peaked at 1,528 MiB of anonymous, kernel and socket memory (anonymous 1,372 MiB, kernel 48 MiB, socket 109 MiB), against 1,741 MiB: 213 MiB (12%) under that limit and 520 MiB (25%) under the limit of 2,048 MiB. No process was killed, `oom` and `oom_kill` stayed at 0, and DNS answered on the server's own port throughout (777 of 777 queries). The group's total reaches 2,048 MiB in every run, because the kernel's file cache fills it and is reclaimed.

1,024 connections in the budget's shape held a group peak of 188 to 194 MiB in this build (188.1 to 188.3 MiB in three runs of that row alone, two of them builds of this round and one a build with one added line of output; 194.5 MiB in a fourth run of that row alone), where the deployed build held 158 MiB. The step comes with the change that ends a connection later: the earlier path ended each of these connections at its first refused request after the figure, and this build serves requests until the byte stop. The measure shows the length of a connection's life and does not place the extra memory in particular allocations. The runs of this row have every connection read to the byte stop, the most that the rules above allow; the connections of the other shapes in the proof's mix are not set to do so.

The table that the server keeps for the headers of its answers is capped at 4 KiB by the locked version of its HTTP/2 library, and the case `test_http2_answers_keep_the_header_table_at_4_kib` holds that. In a run of 2,048 connections held for 3,000 seconds on the build box, with `MALLOC_ARENA_MAX=2`, the group's anonymous memory stayed between 92 and 99 MiB.

Each of the two rate limits (lookups and publications) keeps one entry for each source network that sent a request, an IPv4 address or the /64 of an IPv6 address, with a cap of 131,072 entries: 64 shards of 2,048 entries, each with a lock of its own. A source that arrives at a full shard removes the source in it that was used least recently. A request is a use whether the limit lets it through or refuses it, so a source that keeps sending, a refused one included, goes only if 2,048 other sources reach its shard between two of its requests. The shard of a source is chosen by a hash with a key that is made when the server starts and that a sender cannot see, and each shard's table has a hash with a key of its own, so a sender cannot choose the shard that its sources reach. To remove one given entry from its shard it needs 2,048 other sources that reach that shard after the entry's last use, which is about 131,072 distinct source networks in all. An entry that is removed gives its source one fresh burst (100 lookups, 2 publications) and no more. A shard's table is made for 2,048 entries and can grow to 8,192 buckets under churn. From that rule a full store comes to at most about 16.5 MiB for each limit: 131,072 entries of about 64 bytes and up to 64 tables of 8,192 buckets of 17 bytes. That is an upper figure taken from the rule, not a measure. Beside it, as a separate fact, the process grew by 20.81 MiB (from 31.04 MiB after a warm-up of 3,000 sources to 51.85 MiB) while both limits' stores filled to 131,072 entries each. The code enforces the cap on entries and no limit on resident memory, and neither figure is such a limit. The sweep that removed the entries of quiet sources every 60 seconds is gone, and that changes which entries go: the entry that goes is the one used least recently, which is not always one that has expired, so an indebted entry can go before a newer one that has expired. The server exports the number of entries of each store as `dns_server_rate_limit_lookup_entries` and `dns_server_rate_limit_put_entries`. The cases are `http::rate_limiting::tests::the_store_holds_at_most_its_capacity_however_many_sources_send`, `a_refused_source_stays_indebted_while_others_come_and_go`, `an_entry_that_goes_gives_its_source_one_fresh_burst_and_no_more`, `the_entry_used_least_recently_goes_even_when_a_newer_one_has_expired`, `the_limit_answers_a_refusal_with_the_libraries_headers_and_body` and `each_limiter_reports_the_entries_of_its_own_store`.

The server does not count connections of port 53 over TCP. The DNS library ends one that sends nothing after 1 second. A deployment bounds their number at its firewall; ours allows 1,024 at once, beside its limits for one address and one network.

Not bounded by these figures: the settings of the host's kernel, whose limits on TCP memory and on buffer sizes were larger on the build box than a host of 3.9 GB has.

A deployment builds with `KR_FORK_REV` set to the commit it pins, and compares `/healthz` with
it.

### Dependency: `simple-dns` 0.12.0 with two upstream fixes

The root `Cargo.toml` takes the DNS packet library `simple-dns` from
[`kalapowered/simple-dns`](https://github.com/kalapowered/simple-dns) at commit
`def27859a02d7f38391f0e3f9d9fcf33e51d05ce`, in place of the registry's 0.12.0, through
`[patch.crates-io]`. The registry's 0.12.0 lacks two fixes that upstream released in 0.13.1:
"limit items vec capacity when parsing packets" and "Return write errors when DNS output buffers
fill". That source is the 0.12.0 release with those two upstream commits picked onto it as they
are, and without the crate repository's `bind9` submodule, which only the crate's `bind9-tests`
package uses, so that a build fetches nothing from another host. `iroh`, `iroh-dns`,
`iroh-dns-server` and the registry package `n0-dns-resolver` require the crate's `0.12` line, so an
update cannot bring the fixes. The entry, and the git source it gives the crate in `Cargo.lock`,
go when the workspace can take a release of the crate that holds both fixes, which is version
0.13.1 or later; 0.13.0 holds neither.

Tests, in the crate's fork, `simple-dns/src/dns/packet.rs`, module `tests`:
`plain_bounded_packet_writer_returns_errors_when_full` and
`compressed_bounded_packet_writer_returns_errors_when_full`.

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
