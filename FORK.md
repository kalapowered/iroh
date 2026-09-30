# KalaReach fork of iroh

This is KalaReach's fork of [`n0-computer/iroh`](https://github.com/n0-computer/iroh). Two services
build from it, and both pin a commit of the `kalareach` branch:

- the relay (`iroh-relay`, with a forwarding hook upstream does not have), and
- the discovery server (`iroh-dns-server`, with the fixes listed below).

The client links the published `iroh` crate, not this fork.

The tip of `kalareach` is what the deployments pin. Its history is never rewritten and never
force-pushed: a rewrite would orphan a commit a running service was built from.

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
it is read from the sender and written to the receiver, and is told what became of every payload it
admitted. Upstream's admission callout decides whether a connection is accepted, and nothing about
the payloads that follow. The default policy, `ForwardAll`, forwards everything.

Tests, in `iroh-relay/src/server/clients.rs`, module `forwarding_policy_tests`:
`a_payload_with_nowhere_to_go_is_settled_as_dropped`,
`a_delivered_payload_is_settled_once_as_committed` and
`a_payload_the_destination_refuses_is_settled_as_dropped`.

### Discovery server (`iroh-dns-server`)

| Change | Why | Tests, in `iroh-dns-server/src` |
| --- | --- | --- |
| The packet store's writer tells the zone cache about every packet it replaces or removes. | Eviction removed a packet from the store and left it in the cache, so DNS answered with a record `GET /pkarr/{key}` already reported absent. | `store::tests::an_evicted_record_is_not_answered_from_the_cache`, `store::tests::evicting_one_endpoint_leaves_another_endpoints_zone_cached`, `store::tests::a_record_that_has_not_expired_stays_cached_through_an_eviction_pass`, `store::tests::a_publication_the_store_applied_reaches_the_cache_without_its_caller`, `store::signed_packets::tests::the_writer_reports_each_change_it_applies_and_no_other`, `store::signed_packets::tests::an_eviction_is_reported_while_its_transaction_is_still_open` |
| A lookup caches what it read from the store only if no change to that key's packet happened since it started. | A lookup that overlapped a publication put the older packet back in the cache. | `store::tests::a_lookup_that_overlaps_a_publication_cannot_restore_the_older_packet`, `store::tests::a_lookup_that_overlaps_an_eviction_cannot_restore_the_evicted_packet`, `store::tests::a_lookup_with_no_overlap_caches_the_packet_it_read`, `store::tests::a_lookup_never_changes_the_packet_store` |
| `lookup_rate_limit`: one quota per source network (an IPv4 address, or an IPv6 /64) for `GET /pkarr/{key}` and `/dns-query` by `GET` and `POST`; 50 a second, 100 at once. | Only `PUT /pkarr` had a request limit. | `http::tests::rate_limits::*`, `http::rate_limiting::tests::*`, `config::tests::*` |
| A publication signed more than ten minutes ahead of the server's clock is refused with `400`. | Eviction counts from the signed time, so a packet signed in the future stayed for ever. | `http::tests::publication::*`, `store::tests::a_timestamp_exactly_at_the_allowed_margin_is_accepted_and_one_microsecond_more_is_not`, `store::tests::timestamps_in_the_past_and_at_the_clock_are_accepted_and_the_largest_is_not`, `store::tests::a_refused_publication_changes_neither_the_store_nor_the_cache` |
| `/healthz` reports `git_hash` from `KR_FORK_REV` at build time. | The stock build and this one answered alike. | `http::tests::health::*` |

A deployment builds with `KR_FORK_REV` set to the commit it pins, and compares `/healthz` with
it.

## Merging an upstream security release

An upstream release that fixes a vulnerability in `iroh`, `iroh-relay`, `iroh-dns-server`,
`iroh-dns` or `iroh-base` reaches the fork by a **merge**, never a rebase.

1. Fetch the upstream tag. Create `merge/upstream-<version>` from `kalareach` and merge the tag
   into it. Resolve conflicts by keeping the relay's forwarding hook and the discovery fixes above.
2. Run the suites of the two services: `cargo test --locked -p iroh-relay --features server` and
   `cargo test --locked -p iroh-dns-server`. Every test named above must still exist and pass. A patch upstream has replaced is removed
   together with its tests and the row above.
3. Before rollout, test the merged relay and discovery server against the released client version
   the release matrix supports, and against the previous one: a network tier is compatible with the
   installed clients before a client that needs the new behaviour ships.
4. Fast-forward `kalareach` to the merge branch.
5. In one change to the web repository, move `IROH_RELAY_FORK_REV` (`infra/relay/deployment.env`)
   and `IROH_DNS_SERVER_FORK_REV` (`infra/discovery/deployment.env`) to the new tip and
   `IROH_UPSTREAM_BASE_REV` in both to the merged upstream commit, then deploy both services.
6. Update the base table above.

A fix that a merge cannot deliver in time, because the release also carries changes that need
review, may be cherry-picked onto a branch from `kalareach` instead. A cherry-pick leaves the
crate versions where they were, so the daily check keeps reporting the advisory until it is
acknowledged in `infra/scripts/upstream-security.acknowledgements.json` with the fork commit that
carries the fix. The merge follows when the review is done.

The client links the published `iroh` crate. A release that fixes the client side is a dependency
step in the client's own repository, scheduled through the release matrix; the check says so when
an advisory names one of these crates.

### How fast

| Advisory | Merged within | Deployed |
| --- | --- | --- |
| High or critical severity, or no severity given, naming a crate the fork ships | 3 days of publication | the day it merges |
| Any other advisory naming one of those crates, or a dependency both services lock | 14 days of publication | with the merge |

An upstream release without an advisory sets no deadline. It waits for the next scheduled
dependency step, and the check does not fail on it.

### How a lapse is noticed

`infra/scripts/upstream-security.mjs` in the web repository runs daily as the
`upstream-security` workflow, and on demand. It compares the locked version of every package that
ships in the relay and in the discovery server against the RustSec database and against GitHub's
published advisories for the five crates above. It exits `1`, naming each advisory, its patched
version and its deadline, when an advisory applies and is not acknowledged, and `2` when a source
cannot be read. A failed run is the notice.
