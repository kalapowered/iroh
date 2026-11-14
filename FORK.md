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
| Connections are bounded. A connection with no request in progress for 30 seconds is closed: one that sends nothing after its handshake, an HTTP/2 connection with no request open whatever its peer sends, an idle keep-alive connection. A request has ten seconds from its headers to its answer, body included (`408` after). The body of `PUT /pkarr/{key}` is at most 1,072 bytes, the largest signed packet less the public key, and the body of `POST /dns-query` at most 4,096 bytes, the most the UDP path reads; past that is `413`. The listen backlog is 1024 by default (`listen_backlog`). The TLS handshake and the HTTP/1 header read have 30 seconds each. | Upstream bounded only the handshake and the HTTP/1 header read, and left the three cases above open: a connection that is silent after its handshake, an idle HTTP/2 connection, and a body that stops arriving or is as large as 2 MiB, each of which a sender could hold for as long as it liked. | `http::idle::tests::*`, `http::tests::test_silent_connection_closed`, `http::tests::test_silent_tls_connection_closed`, `http::tests::test_http2_connection_with_no_request_closed`, `http::tests::test_slow_request_body_gets_408`, `http::tests::test_body_limits`; upstream's `http::tests::test_idle_connection_closed`, `http::tests::test_listen_backlog` (Linux only) and `http::tls::tests::test_handshake_timeout`, which arrive with the fork's copy of upstream's two commits and which a later merge of upstream keeps as its own |

These bounds do not stop a party that has many networks and keeps sending: it can hold the server's
connections open by sending a request on each one every 30 seconds, and its requests are limited to ten
seconds and a few kilobytes each. What bounds that party is the host: the firewall's caps on connections for
each source address and each source network, and the service's descriptor and memory limits. The
bounds above make each held connection cost the party a request every 30 seconds. A held connection
costs the server about 26 KB (65,000 held TLS connections, each sending a request every 20 seconds,
measured 1.62 GiB resident on a release build on Linux), so the service's 2 GiB limit and its 65,536
descriptors are what such a party runs into.

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
