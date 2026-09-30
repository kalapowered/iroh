# KalaReach fork of iroh

This is KalaReach's fork of [`n0-computer/iroh`](https://github.com/n0-computer/iroh). Two
services build from it, and each pins a commit of the `kalareach` branch:

- the relay (`iroh-relay`, with a forwarding hook upstream does not have), and
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

### Discovery server (`iroh-dns-server`)

| Change | Why | Tests, in `iroh-dns-server/src` |
| --- | --- | --- |
| The packet store's writer tells the zone cache about every packet it replaces or removes. | Eviction removed a packet from the store and left it in the cache, so DNS answered with a record `GET /pkarr/{key}` already reported absent. | `store::tests::an_evicted_record_is_not_answered_from_the_cache`, `store::tests::evicting_one_endpoint_leaves_another_endpoints_zone_cached`, `store::tests::a_record_that_has_not_expired_stays_cached_through_an_eviction_pass`, `store::tests::a_publication_the_store_applied_reaches_the_cache_without_its_caller`, `store::tests::a_cache_left_in_doubt_by_a_panic_starts_over_and_counts_a_change_for_every_key`, `store::signed_packets::tests::the_writer_reports_each_change_it_applies_and_no_other`, `store::signed_packets::tests::an_eviction_is_reported_while_its_transaction_is_still_open`, `store::signed_packets::tests::a_packet_that_has_not_expired_is_not_reported_by_a_check` |
| A lookup caches what it read from the store only if no change to that key's packet happened since it started. | A lookup that overlapped a publication put the older packet back in the cache. | `store::tests::a_lookup_that_overlaps_a_publication_cannot_restore_the_older_packet`, `store::tests::a_lookup_that_overlaps_an_eviction_cannot_restore_the_evicted_packet`, `store::tests::a_lookup_with_no_overlap_caches_the_packet_it_read`, `store::tests::a_lookup_never_changes_the_packet_store`, `store::tests::a_dht_zone_is_not_cached_if_the_stored_packet_changed_during_the_lookup` |
| `lookup_rate_limit`: one quota per source network (an IPv4 address, or an IPv6 /64) for `GET /pkarr/{key}` and `/dns-query` by `GET` and `POST`; 50 a second, 100 at once. | Only `PUT /pkarr` had a request limit. | `http::tests::rate_limits::*`, `http::rate_limiting::tests::*`, `config::tests::*` |
| A publication signed more than ten minutes ahead of the server's clock is refused with `400`. | Eviction counts from the signed time, so a packet signed in the future stayed until its signed date plus the retention period. | `http::tests::publication::*`, `store::tests::a_timestamp_exactly_at_the_allowed_margin_is_accepted_and_one_microsecond_more_is_not`, `store::tests::timestamps_in_the_past_and_at_the_clock_are_accepted_and_the_largest_is_not`, `store::tests::a_refused_publication_changes_neither_the_store_nor_the_cache` |
| `/healthz` reports `git_hash` from `KR_FORK_REV` at build time. | The stock build and this one answered alike. | `http::tests::health::*` |

A deployment builds with `KR_FORK_REV` set to the commit it pins, and compares `/healthz` with
it.

## Fixing a vulnerability

The daily check reads the lockfiles that build the two deployed binaries: the fork's `Cargo.lock`
at the discovery pin, and `infra/relay/kr-relay/Cargo.lock` in the web repository for the relay.
An advisory applies when the version a lockfile holds is in its affected range.

### An upstream release of an iroh crate

A release that fixes a vulnerability in `iroh`, `iroh-relay`, `iroh-dns-server`, `iroh-dns` or
`iroh-base` reaches the fork by a **merge**, never a rebase.

1. Fetch the upstream tag. Create `merge/upstream-<version>` from `kalareach` and merge the tag
   into it. Resolve conflicts by keeping the relay's forwarding hook and the discovery fixes
   above. Update the base table above on this branch.
2. Run the suites of the two services: `cargo test --locked -p iroh-relay --features server` and
   `cargo test --locked -p iroh-dns-server`. Every test named above must still exist and pass.
   A patch upstream has replaced is removed together with its tests and its row.
3. Before rollout, run the relay wrapper's tests (`cargo test` in `infra/relay/kr-relay` of the
   web repository, with its lockfile at the new fork commit) and the relay and discovery
   end-to-end suites (`scripts/e2e-relay.sh`, `scripts/e2e-discovery.sh`), with the merged
   builds against every client version the signed release matrix supports. A network tier is
   compatible with the installed clients before a client that needs the new behaviour ships.
4. Fast-forward `kalareach` to the merge branch.
5. In one change to the web repository, move `IROH_RELAY_FORK_REV` (`infra/relay/deployment.env`)
   and `IROH_DNS_SERVER_FORK_REV` (`infra/discovery/deployment.env`) to the new tip and
   `IROH_UPSTREAM_BASE_REV` in both to the merged upstream commit, then deploy both services.

A fix that a merge cannot deliver in time, because the release also carries changes that need
review, may be cherry-picked onto a branch from `kalareach` instead. A cherry-pick leaves the
crate versions where they were, so the daily check keeps reporting the advisory until it is
acknowledged in `infra/scripts/upstream-security.acknowledgements.json` with the fork commit that
carries the fix. The merge follows when the review is done.

The client links the published `iroh` crate. A release that fixes the client side is a dependency
step in the client's own repository, scheduled through the release matrix; the check says so when
an advisory names one of these crates, and the acknowledgement records that it is the client's.

### A vulnerability in another package a lockfile holds

A package such as `hickory-server`, `rustls`, `hyper` or `h2` is updated in the lockfile that
holds it, to the patched version: `cargo update -p <package> --precise <version>` on a branch
from `kalareach` for the discovery server's `Cargo.lock`, and the same in
`infra/relay/kr-relay/Cargo.lock` for the relay. Then steps 2 to 5 above, moving only the pin
whose lockfile changed.

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
`upstream-security` workflow, and on demand. It checks every package in the two lockfiles against
the RustSec database, and the five crates above against GitHub's published advisories, because
RustSec carries none for them. It exits `1`, naming each advisory, its patched version and its
deadline, when an advisory applies and is not acknowledged, and `2` when a source cannot be read.
A failed run is the notice.
