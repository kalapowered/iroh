use std::{
    future::Future,
    path::Path,
    result,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use iroh_dns::pkarr::{SignedPacket, Timestamp};
use n0_error::{AnyError, Result, StackResultExt, StdResultExt, anyerr};
use redb::{
    Database, MultimapTableDefinition, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::{metrics::Metrics, util::PublicKeyBytes};

type SignedPacketsKey = [u8; 32];

/// Called by the writer for a key whose stored packet it has just replaced or removed.
///
/// It runs on the writer's thread, before the writer takes its next message: no read of the store
/// that the writer answers after the change can be answered before the callback has run. It must
/// be quick and must not wait for the store.
pub(super) type OnChange = Arc<dyn Fn(&PublicKeyBytes) + Send + Sync>;

/// The ceiling on the number of stored packets when the configuration sets none: a million
/// endpoints, about a gigabyte of packets.
pub(crate) const DEFAULT_MAX_PACKETS: usize = 1_000_000;

/// What the store did with a packet it was offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Upsert {
    /// The packet is stored, as a new endpoint or as a replacement of an older packet.
    Stored,
    /// The store holds a packet for the endpoint that is at least as recent: nothing changed.
    Unchanged,
    /// The store holds [`Options::max_packets`] packets or more and none for this endpoint:
    /// nothing changed.
    Full,
}

const SIGNED_PACKETS_TABLE: TableDefinition<&SignedPacketsKey, &[u8]> =
    TableDefinition::new("signed-packets-1");
const UPDATE_TIME_TABLE: MultimapTableDefinition<[u8; 8], SignedPacketsKey> =
    MultimapTableDefinition::new("update-time-1");

#[derive(Debug)]
pub(super) struct SignedPacketStore {
    send: mpsc::Sender<Message>,
    cancel: CancellationToken,
    max_packets: usize,
    #[cfg(test)]
    options: Options,
    _write_thread: IoThread,
    _evict_thread: Option<IoThread>,
}

impl Drop for SignedPacketStore {
    fn drop(&mut self) {
        // cancel the actor
        self.cancel.cancel();
        // after cancellation, the two threads will be joined
    }
}

#[derive(derive_more::Debug)]
enum Message {
    Upsert {
        packet: SignedPacket,
        res: oneshot::Sender<Upsert>,
    },
    Get {
        key: PublicKeyBytes,
        res: oneshot::Sender<Option<SignedPacket>>,
    },
    #[cfg(test)]
    Remove {
        key: PublicKeyBytes,
        res: oneshot::Sender<bool>,
    },
    Snapshot {
        #[debug(skip)]
        res: oneshot::Sender<Snapshot>,
    },
    CheckExpired {
        time: Timestamp,
        key: PublicKeyBytes,
    },
}

/// Opens the database again after it failed. It runs on a thread of its own: after an I/O error
/// redb repairs the whole file on open, which takes as long as the file is big.
type Reopen = Arc<dyn Fn() -> Result<Database> + Send + Sync>;

/// The answer to a publication: what to send, and the caller to send it to.
type Ack = (oneshot::Sender<Upsert>, Upsert);

struct Actor {
    /// The database, or `None` while a reopen after a failure has not worked.
    db: Option<Database>,
    reopen: Reopen,
    /// The open that is running, and where its result arrives.
    reopening: Option<std::sync::mpsc::Receiver<Result<Database>>>,
    /// When the last open ended, for the pause before the next.
    last_reopen: Option<Instant>,
    /// The number of packets the last commit holds, which the count shows after a batch is rolled
    /// back and the database has not been read again.
    committed: i64,
    /// Set when a batch has failed, until a batch that changed the store has committed. A
    /// publication is acknowledged before its batch commits, which is what makes a batch fast;
    /// while this is set, each batch holds one message and its answer waits for the commit, so a
    /// publication that cannot be stored is refused and not acknowledged.
    failing: bool,
    recv: PeekableReceiver<Message>,
    cancel: CancellationToken,
    options: Options,
    metrics: Arc<Metrics>,
    on_change: OnChange,
}

/// Configuration for the signed-packet store.
///
/// Controls how incoming packets are batched into write transactions and how
/// long packets are retained before the eviction task removes them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Options {
    /// Maximum number of packets to process in a single write transaction.
    pub(crate) max_batch_size: usize,
    /// Maximum time to keep a write transaction open.
    pub(crate) max_batch_time: Duration,
    /// Time to keep packets in the store before eviction.
    pub(crate) eviction: Duration,
    /// Pause between eviction checks.
    pub(crate) eviction_interval: Duration,
    /// The most packets the store holds. At that number a packet for an endpoint the store holds
    /// no packet for is refused, and a packet for a held endpoint is still taken. Nothing is
    /// evicted early to make room.
    pub(crate) max_packets: usize,
    /// The shortest time between two attempts to reopen the database after it failed.
    pub(crate) reopen_pause: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // 64k packets
            max_batch_size: 1024 * 64,
            // this means we lose at most 1 second of data in case of a crash
            max_batch_time: Duration::from_secs(1),
            // 7 days
            eviction: Duration::from_secs(3600 * 24 * 7),
            // eviction can run frequently since it does not do a full scan
            eviction_interval: Duration::from_secs(10),
            max_packets: DEFAULT_MAX_PACKETS,
            reopen_pause: Duration::from_secs(10),
        }
    }
}

impl Actor {
    /// Serve messages until the store is dropped.
    ///
    /// A failed batch does not end the writer: it also answers the reads and the eviction, and
    /// a failed disk is the time those matter. The writer rolls the batch back, opens the
    /// database again and takes the next message.
    async fn run(mut self) {
        while let Some(msg) = self.recv.recv().await {
            match self.serve(msg).await {
                Ok(true) => {}
                Ok(false) => return,
                Err(err) => self.failed(err),
            }
        }
    }

    /// Serve one message and the batch it opens. Returns `false` when the store was dropped
    /// while the batch was open.
    async fn serve(&mut self, msg: Message) -> Result<bool> {
        if self.db.is_none() {
            self.try_reopen();
            if self.db.is_none() {
                // Dropping the message answers its caller with an error.
                debug!("the packet database is not open, a message is refused");
                return Ok(true);
            }
        }
        let mut touched = Vec::new();
        let result = self.batch(msg, &mut touched).await;
        if result.is_err() {
            // The batch is rolled back, so the cache must not keep what the batch put there.
            for key in &touched {
                (self.on_change)(key);
            }
        }
        result
    }

    /// One batch: the message, and what arrives until the batch is full or its time is up.
    ///
    /// Any error ends the batch before its commit, so the transaction is dropped and every
    /// change in it is rolled back.
    async fn batch(&mut self, msg: Message, touched: &mut Vec<PublicKeyBytes>) -> Result<bool> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| anyerr!("the packet database is not open"))?;
        // if we get a snapshot message here we don't need to do a write transaction
        if let Message::Snapshot { res } = msg {
            let snapshot = Snapshot::new(db)?;
            res.send(snapshot).ok();
            return Ok(true);
        }
        trace!("batch");
        let transaction = db.begin_write().anyerr()?;
        let mut tables = Tables::new(&transaction).anyerr()?;
        self.recv.push_back(msg).unwrap();
        let timeout = tokio::time::sleep(self.options.max_batch_time);
        tokio::pin!(timeout);
        let size = if self.failing {
            1
        } else {
            self.options.max_batch_size
        };
        let mut waiting = Vec::new();
        let mut cancelled = false;
        for _ in 0..size {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    cancelled = true;
                    break;
                }
                _ = &mut timeout => break,
                Some(msg) = self.recv.recv() => {
                    if let Some(ack) = self.handle_message(msg, &mut tables, touched)? {
                        if self.failing {
                            waiting.push(ack);
                        } else {
                            ack.0.send(ack.1).ok();
                        }
                    }
                }
            }
        }
        drop(tables);
        transaction.commit().anyerr()?;
        self.committed = self.metrics.store_packets.get();
        for (res, outcome) in waiting {
            res.send(outcome).ok();
        }
        if self.failing && !touched.is_empty() {
            info!("the packet store commits again");
            self.failing = false;
        }
        Ok(!cancelled)
    }

    /// Record a failed batch and get the database ready for the next message.
    fn failed(&mut self, err: AnyError) {
        self.metrics.store_failures.inc();
        self.failing = true;
        // The count shown included the rolled back batch.
        self.metrics.store_packets.set(self.committed);
        error!("packet store write failed, the open batch is rolled back: {err:#}");
        // redb refuses every later operation on a handle after an I/O error, so a handle that
        // can no longer start a write is dropped (which releases the file) and replaced.
        let usable = self.db.as_ref().is_some_and(|db| db.begin_write().is_ok());
        if usable {
            self.refresh_count();
        } else {
            self.db = None;
            self.try_reopen();
        }
    }

    /// Take the result of the open that is running, or start one unless the last ended less than
    /// the pause ago.
    ///
    /// The open does not run on the writer's thread: the writer goes on answering while it runs,
    /// every request it cannot serve with an error, so a lookup fails at once and does not wait for
    /// a repair of the file.
    fn try_reopen(&mut self) {
        if let Some(running) = &self.reopening {
            let result = match running.try_recv() {
                Ok(result) => result,
                Err(std::sync::mpsc::TryRecvError::Empty) => return,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => Err(anyerr!(
                    "the thread that opens the database ended without an answer"
                )),
            };
            self.reopening = None;
            self.last_reopen = Some(Instant::now());
            match result {
                Ok(db) => {
                    info!("packet database reopened");
                    self.db = Some(db);
                    self.refresh_count();
                }
                Err(err) => warn!("packet database did not reopen: {err:#}"),
            }
            return;
        }
        let paused = self
            .last_reopen
            .is_some_and(|at| at.elapsed() < self.options.reopen_pause);
        if paused {
            return;
        }
        self.metrics.store_reopens.inc();
        let (send, recv) = std::sync::mpsc::channel();
        let reopen = self.reopen.clone();
        let spawned = std::thread::Builder::new()
            .name("packet-store-reopen".into())
            .spawn(move || {
                send.send(reopen()).ok();
            });
        match spawned {
            Ok(_) => self.reopening = Some(recv),
            Err(err) => {
                self.last_reopen = Some(Instant::now());
                warn!("could not start the thread that opens the database: {err:#}");
            }
        }
    }

    /// Publish the number of packets the last commit holds, after a batch that did not.
    fn refresh_count(&mut self) {
        let Some(db) = &self.db else { return };
        let count = db
            .begin_read()
            .anyerr()
            .and_then(|tx| tx.open_table(SIGNED_PACKETS_TABLE).anyerr())
            .and_then(|table| table.len().anyerr());
        match count {
            Ok(count) => {
                self.metrics.store_packets.set(count as i64);
                self.committed = count as i64;
            }
            Err(err) => warn!("could not read the number of packets: {err:#}"),
        }
    }

    /// Publish the number of packets the open transaction holds.
    ///
    /// The count is the table's own length, which redb keeps in the table's root and changes
    /// with every insert and removal, so it is exact, costs no scan, and is committed or rolled
    /// back with the rest of the transaction.
    fn record_count(&self, tables: &Tables) -> Result<()> {
        let count = tables.signed_packets.len().anyerr()?;
        self.metrics.store_packets.set(count as i64);
        Ok(())
    }

    /// Apply one message to the open transaction. A publication's answer is returned for the
    /// caller to send, and every key whose stored packet changed is added to `touched` as the
    /// cache is told.
    fn handle_message(
        &self,
        msg: Message,
        tables: &mut Tables,
        touched: &mut Vec<PublicKeyBytes>,
    ) -> Result<Option<Ack>> {
        match msg {
            Message::Get { key, res } => match get_packet(&tables.signed_packets, &key) {
                Ok(packet) => {
                    trace!("get {key}: {}", packet.is_some());
                    res.send(packet).ok();
                }
                Err(err) => {
                    warn!("get {key} failed: {err:#}");
                    return Err(err).context(format!("get packet for {key} failed"));
                }
            },
            Message::Upsert { packet, res } => {
                let key = PublicKeyBytes::from_signed_packet(&packet);
                trace!("upsert {}", key);
                let replaced = match get_packet(&tables.signed_packets, &key)? {
                    Some(existing) => {
                        if existing.more_recent_than(&packet) {
                            return Ok(Some((res, Upsert::Unchanged)));
                        } else {
                            // remove the old packet from the update time index
                            tables
                                .update_time
                                .remove(&existing.timestamp().to_be_bytes(), key.as_bytes())
                                .anyerr()?;
                            true
                        }
                    }
                    None => {
                        // A packet for an endpoint the store holds none for adds a record.
                        let held = tables.signed_packets.len().anyerr()?;
                        if held >= self.options.max_packets as u64 {
                            debug!("refused {key}: the store holds {held} packets");
                            self.metrics.pkarr_publish_store_full.inc();
                            return Ok(Some((res, Upsert::Full)));
                        }
                        false
                    }
                };
                let value = serialize(&packet);
                tables
                    .signed_packets
                    .insert(key.as_bytes(), &value[..])
                    .anyerr()?;
                tables
                    .update_time
                    .insert(&packet.timestamp().to_be_bytes(), key.as_bytes())
                    .anyerr()?;
                if replaced {
                    self.metrics.store_packets_updated.inc();
                } else {
                    self.metrics.store_packets_inserted.inc();
                }
                self.record_count(tables)?;
                self.changed(key, touched);
                return Ok(Some((res, Upsert::Stored)));
            }
            #[cfg(test)]
            Message::Remove { key, res } => {
                trace!("remove {}", key);
                let removed = tables
                    .signed_packets
                    .remove(key.as_bytes())
                    .anyerr()?
                    .map(|row| deserialize(row.value()))
                    .transpose()?;
                let updated = match removed {
                    Some(packet) => {
                        tables
                            .update_time
                            .remove(&packet.timestamp().to_be_bytes(), key.as_bytes())
                            .anyerr()?;
                        self.metrics.store_packets_removed.inc();
                        self.record_count(tables)?;
                        self.changed(key, touched);
                        true
                    }
                    _ => false,
                };
                res.send(updated).ok();
            }
            Message::Snapshot { res } => {
                trace!("snapshot");
                let db = self
                    .db
                    .as_ref()
                    .ok_or_else(|| anyerr!("the packet database is not open"))?;
                res.send(Snapshot::new(db)?).ok();
            }
            Message::CheckExpired { key, time } => {
                trace!("check expired {} at {}", key, fmt_time(time));
                match get_packet(&tables.signed_packets, &key)? {
                    Some(packet) => {
                        let expiry_us = self.options.eviction.as_micros() as u64;
                        let expired = Timestamp::from_micros(
                            Timestamp::now().as_micros().saturating_sub(expiry_us),
                        );
                        if packet.timestamp() < expired {
                            tables
                                .update_time
                                .remove(&time.to_be_bytes(), key.as_bytes())
                                .anyerr()?;
                            let _ = tables.signed_packets.remove(key.as_bytes()).anyerr()?;
                            self.metrics.store_packets_expired.inc();
                            self.record_count(tables)?;
                            self.changed(key, touched);
                            debug!("removed expired packet {key}");
                        } else {
                            debug!(
                                "packet {key} is no longer expired, removing obsolete expiry entry"
                            );
                            tables
                                .update_time
                                .remove(&time.to_be_bytes(), key.as_bytes())
                                .anyerr()?;
                        }
                    }
                    None => {
                        debug!("expired packet {key} not found, remove from expiry table");
                        tables
                            .update_time
                            .remove(&time.to_be_bytes(), key.as_bytes())
                            .anyerr()?;
                    }
                }
            }
        }
        Ok(None)
    }

    /// Tell the cache that a key's stored packet changed, and remember the key: if the batch
    /// fails the change is rolled back, and the cache is told again.
    fn changed(&self, key: PublicKeyBytes, touched: &mut Vec<PublicKeyBytes>) {
        (self.on_change)(&key);
        touched.push(key);
    }
}

fn fmt_time(t: Timestamp) -> String {
    let duration = std::time::Duration::from_micros(t.as_micros());
    humantime::format_rfc3339_micros(SystemTime::UNIX_EPOCH + duration).to_string()
}

/// A struct similar to [`redb::Table`] but for all tables that make up the
/// signed packet store.
struct Tables<'a> {
    pub signed_packets: redb::Table<'a, &'static SignedPacketsKey, &'static [u8]>,
    pub update_time: redb::MultimapTable<'a, [u8; 8], SignedPacketsKey>,
}

impl<'txn> Tables<'txn> {
    fn new(tx: &'txn redb::WriteTransaction) -> result::Result<Self, redb::TableError> {
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE)?,
            update_time: tx.open_multimap_table(UPDATE_TIME_TABLE)?,
        })
    }
}

struct Snapshot {
    #[allow(dead_code)]
    pub signed_packets: redb::ReadOnlyTable<&'static SignedPacketsKey, &'static [u8]>,
    pub update_time: redb::ReadOnlyMultimapTable<[u8; 8], SignedPacketsKey>,
}

impl Snapshot {
    fn new(db: &Database) -> Result<Self> {
        let tx = db.begin_read().anyerr()?;
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE).anyerr()?,
            update_time: tx.open_multimap_table(UPDATE_TIME_TABLE).anyerr()?,
        })
    }
}

/// The reopen of a store that is not in a file: there is nothing to open again.
#[cfg(test)]
fn no_reopen() -> Reopen {
    Arc::new(|| Err(anyerr!("an in-memory packet store cannot be opened again")))
}

impl SignedPacketStore {
    pub(crate) fn persistent(
        path: impl AsRef<Path>,
        options: Options,
        metrics: Arc<Metrics>,
        on_change: OnChange,
    ) -> Result<Self> {
        let path = path.as_ref();
        info!("loading packet database from {}", path.to_string_lossy());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_std_context(|_| {
                format!(
                    "failed to create database directory at {}",
                    path.to_string_lossy()
                )
            })?;
        }
        let db = Database::builder()
            .create(path)
            .std_context("failed to open packet database")?;
        let path = path.to_path_buf();
        // Open, and not create: a file that is gone is not an empty store to carry on with.
        let reopen: Reopen = Arc::new(move || {
            Database::builder()
                .open(&path)
                .std_context("failed to reopen packet database")
        });
        Self::open(db, options, metrics, on_change, true, reopen)
    }

    #[cfg(test)]
    pub(crate) fn in_memory(
        options: Options,
        metrics: Arc<Metrics>,
        on_change: OnChange,
    ) -> Result<Self> {
        info!("using in-memory packet database");
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .anyerr()?;
        Self::open(db, options, metrics, on_change, true, no_reopen())
    }

    /// An in-memory store whose periodic eviction task does not run: eviction happens only when
    /// [`Self::evict_expired`] is called, so a test decides when.
    #[cfg(test)]
    pub(crate) fn in_memory_manual_eviction(
        options: Options,
        metrics: Arc<Metrics>,
        on_change: OnChange,
    ) -> Result<Self> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .anyerr()?;
        Self::open(db, options, metrics, on_change, false, no_reopen())
    }

    /// A store over a backend the test controls, whose periodic eviction task runs only when
    /// `run_eviction_task` is set.
    #[cfg(test)]
    pub(crate) fn with_backend(
        backend: impl redb::StorageBackend + Clone,
        options: Options,
        metrics: Arc<Metrics>,
        on_change: OnChange,
        run_eviction_task: bool,
    ) -> Result<Self> {
        let again = backend.clone();
        let reopen: Reopen = Arc::new(move || {
            Database::builder()
                .create_with_backend(again.clone())
                .anyerr()
        });
        Self::with_backend_and_reopen(
            backend,
            options,
            metrics,
            on_change,
            run_eviction_task,
            reopen,
        )
    }

    /// [`Self::with_backend`] with the function that opens the database again named.
    #[cfg(test)]
    pub(crate) fn with_backend_and_reopen(
        backend: impl redb::StorageBackend,
        options: Options,
        metrics: Arc<Metrics>,
        on_change: OnChange,
        run_eviction_task: bool,
        reopen: Reopen,
    ) -> Result<Self> {
        let db = Database::builder().create_with_backend(backend).anyerr()?;
        Self::open(db, options, metrics, on_change, run_eviction_task, reopen)
    }

    pub(crate) fn open(
        db: Database,
        options: Options,
        metrics: Arc<Metrics>,
        on_change: OnChange,
        run_eviction_task: bool,
        reopen: Reopen,
    ) -> Result<Self> {
        // create tables
        let write_tx = db.begin_write().anyerr()?;
        let tables = Tables::new(&write_tx).anyerr()?;
        let stored = tables.signed_packets.len().anyerr()?;
        drop(tables);
        write_tx.commit().anyerr()?;
        metrics.store_packets.set(stored as i64);
        metrics.store_packets_max.set(options.max_packets as i64);
        let (send, recv) = mpsc::channel(1024);
        let send2 = send.clone();
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let cancel3 = cancel.clone();
        let actor = Actor {
            db: Some(db),
            reopen,
            reopening: None,
            last_reopen: None,
            committed: stored as i64,
            failing: false,
            recv: PeekableReceiver::new(recv),
            cancel: cancel2,
            options,
            metrics,
            on_change,
        };
        // start an io thread and donate it to the tokio runtime so we can do blocking IO
        // inside the thread despite being in a tokio runtime
        let _write_thread = IoThread::new("packet-store-actor", move || actor.run())?;
        let _evict_thread = if run_eviction_task {
            Some(IoThread::new("packet-store-evict", move || {
                evict_task(send2, options, cancel3)
            })?)
        } else {
            None
        };
        Ok(Self {
            send,
            cancel,
            max_packets: options.max_packets,
            #[cfg(test)]
            options,
            _write_thread,
            _evict_thread,
        })
    }

    /// Run one eviction pass, the one the periodic task runs, and return once the writer has
    /// handled every packet the pass checked.
    ///
    /// The writer takes messages in order, so the answer to a read sent after the pass shows that
    /// the pass is done.
    #[cfg(test)]
    pub(crate) async fn evict_expired(&self) -> Result<()> {
        evict_expired_once(&self.send, self.options).await?;
        let (tx, rx) = oneshot::channel();
        // Any key does: the writer answers the read after everything queued before it.
        let barrier =
            PublicKeyBytes::new_unchecked(*iroh_base::SecretKey::generate().public().as_bytes());
        self.send
            .send(Message::Get {
                key: barrier,
                res: tx,
            })
            .await
            .anyerr()?;
        rx.await.anyerr()?;
        Ok(())
    }

    /// The most packets the store holds.
    pub(crate) fn max_packets(&self) -> usize {
        self.max_packets
    }

    pub(crate) async fn upsert(&self, packet: SignedPacket) -> Result<Upsert> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Upsert { packet, res: tx })
            .await
            .anyerr()?;
        rx.await.anyerr()
    }

    pub(crate) async fn get(&self, key: &PublicKeyBytes) -> Result<Option<SignedPacket>> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Get { key: *key, res: tx })
            .await
            .anyerr()?;
        rx.await.anyerr()
    }

    #[cfg(test)]
    pub(crate) async fn remove(&self, key: &PublicKeyBytes) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Remove { key: *key, res: tx })
            .await
            .anyerr()?;
        rx.await.anyerr()
    }
}

/// Serialize a signed packet for storage: `<8 bytes last_seen><packet bytes>`.
fn serialize(packet: &SignedPacket) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + packet.as_bytes().len());
    out.extend_from_slice(&Timestamp::now().to_be_bytes());
    out.extend_from_slice(packet.as_bytes());
    out
}

/// Deserialize a signed packet from storage format.
///
/// Handles backwards compatibility with older storage formats that didn't include
/// the `last_seen` prefix.
fn deserialize(data: &[u8]) -> Result<SignedPacket> {
    // Try parsing as <8 bytes last_seen><packet> (pkarr v3 format)
    if data.len() >= 8
        && let Ok(packet) = SignedPacket::from_bytes_unchecked(&data[8..])
    {
        return Ok(packet);
    }
    // Fall back to raw packet bytes (pre-v0.35 format without last_seen prefix)
    SignedPacket::from_bytes_unchecked(data)
        .map_err(|err| anyerr!("Failed to decode stored packet: {err:#}"))
}

fn get_packet(
    table: &impl ReadableTable<&'static SignedPacketsKey, &'static [u8]>,
    key: &PublicKeyBytes,
) -> Result<Option<SignedPacket>> {
    let Some(row) = table
        .get(key.as_ref())
        .std_context("database fetch failed")?
    else {
        return Ok(None);
    };
    Ok(Some(deserialize(row.value())?))
}

async fn evict_task(send: mpsc::Sender<Message>, options: Options, cancel: CancellationToken) {
    let cancel2 = cancel.clone();
    let _ = cancel2
        .run_until_cancelled(async move {
            info!("starting evict task");
            evict_loop(
                || evict_expired_once(&send, options),
                options.eviction_interval,
                || send.is_closed(),
            )
            .await;
            cancel.cancel();
        })
        .await;
}

/// Run `pass` every `interval` until the writer is gone.
///
/// A pass that fails, because the store is failing or reopening, is logged and the next one runs
/// after the interval: the task ends only when there is no writer to ask.
async fn evict_loop<F, Fut>(mut pass: F, interval: Duration, writer_gone: impl Fn() -> bool)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    while !writer_gone() {
        if let Err(cause) = pass().await {
            warn!("eviction pass failed, the next one runs after the interval: {cause:#}");
        }
        tokio::time::sleep(interval).await;
    }
}

/// One eviction pass: take a snapshot of the store and have the writer check every packet the
/// snapshot lists as older than the retention window.
async fn evict_expired_once(send: &mpsc::Sender<Message>, options: Options) -> Result<()> {
    let expiry_us = options.eviction.as_micros() as u64;
    let (tx, rx) = oneshot::channel();
    let _ = send.send(Message::Snapshot { res: tx }).await.ok();
    // if we can't get the snapshot we exit the loop, main actor dead
    let snapshot = rx.await.std_context("failed to get snapshot")?;

    let expired = Timestamp::from_micros(Timestamp::now().as_micros().saturating_sub(expiry_us));
    trace!("evicting packets older than {}", fmt_time(expired));
    // if getting the range fails we exit the loop and shut down
    // if individual reads fail we log the error and limp on
    for item in snapshot
        .update_time
        .range(..expired.to_be_bytes())
        .anyerr()?
    {
        let (time, keys) = match item {
            Ok(v) => v,
            Err(e) => {
                error!("failed to read update_time row {:?}", e);
                continue;
            }
        };
        let time = Timestamp::from_be_bytes(time.value());
        trace!("evicting expired packets at {}", fmt_time(time));
        for item in keys {
            let key = match item {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "failed to read update_time item at {}: {:?}",
                        fmt_time(time),
                        e
                    );
                    continue;
                }
            };
            // Safety: bytes were originally written from a validated PublicKey.
            // If the database is corrupt, to_z32() may panic downstream.
            let key = PublicKeyBytes::new_unchecked(key.value());

            debug!("evicting expired packet {} {}", fmt_time(time), key);
            send.send(Message::CheckExpired { time, key })
                .await
                .anyerr()?;
        }
    }
    Ok(())
}

/// An io thread that drives a future to completion on the current tokio runtime
///
/// Inside the future, blocking IO can be done without blocking one of the tokio
/// pool threads.
#[derive(Debug)]
struct IoThread {
    handle: Option<std::thread::JoinHandle<()>>,
}

impl IoThread {
    /// Spawn a new io thread.
    ///
    /// Calling this function requires that the current thread is running in a
    /// tokio runtime. It is up to the caller to make sure the future exits,
    /// e.g. by using a cancellation token. Otherwise, drop will block.
    fn new<F, Fut>(name: &str, f: F) -> Result<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        let rt = tokio::runtime::Handle::try_current().std_context("get tokio handle")?;
        let handle = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || rt.block_on(f()))
            .std_context("failed to spawn thread")?;
        Ok(Self {
            handle: Some(handle),
        })
    }
}

impl Drop for IoThread {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A wrapper for a tokio mpsc receiver that allows peeking at the next message.
#[derive(Debug)]
struct PeekableReceiver<T> {
    msg: Option<T>,
    recv: tokio::sync::mpsc::Receiver<T>,
}

#[allow(dead_code)]
impl<T> PeekableReceiver<T> {
    fn new(recv: tokio::sync::mpsc::Receiver<T>) -> Self {
        Self { msg: None, recv }
    }

    /// Receive the next message.
    ///
    /// Will block if there are no messages.
    /// Returns None only if there are no more messages (sender is dropped).
    async fn recv(&mut self) -> Option<T> {
        if let Some(msg) = self.msg.take() {
            return Some(msg);
        }
        self.recv.recv().await
    }

    /// Push back a message. This will only work if there is room for it.
    /// Otherwise, it will fail and return the message.
    fn push_back(&mut self, msg: T) -> std::result::Result<(), T> {
        if self.msg.is_none() {
            self.msg = Some(msg);
            Ok(())
        } else {
            Err(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;
    use crate::testing::{DAY_MICROS, Disk, FullDisk, signed_packet_at};

    fn test_signed_packet() -> SignedPacket {
        let secret_key = SecretKey::generate();
        SignedPacket::from_txt_strings(&secret_key, "_iroh", ["relay=https://example.com"], 30)
            .expect("valid packet")
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let packet = test_signed_packet();
        let serialized = serialize(&packet);
        let deserialized = deserialize(&serialized).expect("roundtrip should succeed");
        assert_eq!(packet.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn deserialize_old_format_without_last_seen_prefix() {
        // Pre-v0.35 format: raw SignedPacket bytes without the 8-byte last_seen prefix
        let packet = test_signed_packet();
        let old_format = packet.as_bytes().to_vec();
        let deserialized = deserialize(&old_format).expect("old format should be readable");
        assert_eq!(packet.as_bytes(), deserialized.as_bytes());
    }

    /// A hook that records the keys it is called with.
    fn recording_hook() -> (OnChange, Arc<std::sync::Mutex<Vec<PublicKeyBytes>>>) {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let hook: OnChange = {
            let calls = calls.clone();
            Arc::new(move |key| calls.lock().expect("calls").push(*key))
        };
        (hook, calls)
    }

    fn no_hook() -> OnChange {
        Arc::new(|_| {})
    }

    #[tokio::test]
    async fn remove_in_memory() {
        let store = SignedPacketStore::in_memory(
            Options::default(),
            Arc::new(Metrics::default()),
            no_hook(),
        )
        .expect("in-memory store");
        let packet = test_signed_packet();
        let key = PublicKeyBytes::from_signed_packet(&packet);

        assert_eq!(
            store.upsert(packet.clone()).await.expect("upsert"),
            Upsert::Stored
        );
        assert!(store.get(&key).await.expect("get").is_some());

        assert!(store.remove(&key).await.expect("remove existing"));
        assert!(store.get(&key).await.expect("get after remove").is_none());

        assert!(!store.remove(&key).await.expect("remove missing"));
    }

    #[tokio::test]
    async fn the_writer_reports_each_change_it_applies_and_no_other() {
        let (hook, calls) = recording_hook();
        let store = SignedPacketStore::in_memory_manual_eviction(
            Options::default(),
            Arc::new(Metrics::default()),
            hook,
        )
        .expect("in-memory store");
        let secret_key = SecretKey::generate();
        let now = Timestamp::now().as_micros();
        let newer = signed_packet_at(&secret_key, now + 1, "newer");
        let older = signed_packet_at(&secret_key, now, "older");
        let key = PublicKeyBytes::from_signed_packet(&newer);
        let count = || calls.lock().expect("calls").len();

        assert_eq!(
            store.upsert(newer.clone()).await.expect("first upsert"),
            Upsert::Stored
        );
        assert_eq!(count(), 1, "a new packet is a change");

        // The store keeps the newer packet, so nothing changed and nobody is told.
        assert_eq!(
            store.upsert(older).await.expect("older upsert"),
            Upsert::Unchanged
        );
        assert_eq!(count(), 1, "a refused upsert is not a change");

        assert!(store.remove(&key).await.expect("remove"));
        assert_eq!(count(), 2, "a removal is a change");
        assert!(!store.remove(&key).await.expect("remove missing"));
        assert_eq!(count(), 2, "removing nothing is not a change");
        assert!(
            calls
                .lock()
                .expect("calls")
                .iter()
                .all(|called| *called == key)
        );
    }

    #[tokio::test]
    async fn an_eviction_is_reported_while_its_transaction_is_still_open() {
        // A batch that neither fills nor times out, so nothing in this test is committed: the
        // report has to come from the removal, not from a commit.
        let options = Options {
            max_batch_size: 1000,
            max_batch_time: Duration::from_secs(3600),
            eviction: Duration::from_secs(24 * 3600),
            eviction_interval: Duration::from_secs(3600),
            ..Options::default()
        };
        let (hook, calls) = recording_hook();
        let store = SignedPacketStore::in_memory_manual_eviction(
            options,
            Arc::new(Metrics::default()),
            hook,
        )
        .expect("in-memory store");
        let secret_key = SecretKey::generate();
        let signed = Timestamp::now().as_micros() - 2 * 24 * 3600 * 1_000_000;
        let packet = signed_packet_at(&secret_key, signed, "old");
        let key = PublicKeyBytes::from_signed_packet(&packet);
        assert_eq!(
            store.upsert(packet.clone()).await.expect("upsert"),
            Upsert::Stored
        );
        let before = calls.lock().expect("calls").len();

        store
            .send
            .send(Message::CheckExpired {
                time: packet.timestamp(),
                key,
            })
            .await
            .expect("send");
        // The writer answers this read after the check, in the same open transaction.
        assert!(store.get(&key).await.expect("get").is_none());

        assert_eq!(calls.lock().expect("calls").len(), before + 1);
    }

    #[tokio::test]
    async fn a_packet_that_has_not_expired_is_not_reported_by_a_check() {
        let (hook, calls) = recording_hook();
        let store = SignedPacketStore::in_memory_manual_eviction(
            Options {
                max_batch_size: 1,
                max_batch_time: Duration::from_secs(3600),
                ..Options::default()
            },
            Arc::new(Metrics::default()),
            hook,
        )
        .expect("in-memory store");
        let packet = test_signed_packet();
        let key = PublicKeyBytes::from_signed_packet(&packet);
        assert_eq!(
            store.upsert(packet.clone()).await.expect("upsert"),
            Upsert::Stored
        );
        let before = calls.lock().expect("calls").len();

        store
            .send
            .send(Message::CheckExpired {
                time: packet.timestamp(),
                key,
            })
            .await
            .expect("send");
        assert!(store.get(&key).await.expect("get").is_some());

        assert_eq!(calls.lock().expect("calls").len(), before);
    }

    /// A store that holds at most `max_packets` packets, evicts a packet a day after its signed
    /// time and only when a test asks, and closes a write transaction after each packet.
    fn ceiling_store(max_packets: usize) -> (SignedPacketStore, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::default());
        let store = SignedPacketStore::in_memory_manual_eviction(
            Options {
                max_batch_size: 1,
                max_batch_time: Duration::from_secs(3600),
                eviction: Duration::from_secs(24 * 3600),
                max_packets,
                ..Options::default()
            },
            metrics.clone(),
            no_hook(),
        )
        .expect("in-memory store");
        (store, metrics)
    }

    fn endpoint_key(secret_key: &SecretKey) -> PublicKeyBytes {
        PublicKeyBytes::new_unchecked(*secret_key.public().as_bytes())
    }

    #[tokio::test]
    async fn a_store_at_its_ceiling_takes_a_replacement_and_refuses_a_new_endpoint() {
        let (store, metrics) = ceiling_store(3);
        let endpoints: Vec<_> = (0..3).map(|_| SecretKey::generate()).collect();
        let now = Timestamp::now().as_micros();
        for endpoint in &endpoints {
            let packet = signed_packet_at(endpoint, now, "first");
            assert_eq!(store.upsert(packet).await.expect("upsert"), Upsert::Stored);
        }
        assert_eq!(metrics.store_packets.get(), 3);

        // A packet that replaces a stored one adds no record, so it is taken.
        let replacement = signed_packet_at(&endpoints[0], now + 1, "second");
        assert_eq!(
            store
                .upsert(replacement.clone())
                .await
                .expect("replacement"),
            Upsert::Stored
        );
        let kept = store.get(&endpoint_key(&endpoints[0])).await.expect("get");
        assert_eq!(kept.expect("stored").as_bytes(), replacement.as_bytes());

        // An older packet for a stored endpoint is not a refusal: the store keeps what it has.
        let older = signed_packet_at(&endpoints[1], now - 1, "older");
        assert_eq!(store.upsert(older).await.expect("older"), Upsert::Unchanged);

        // An endpoint the store holds nothing for is refused, and not stored.
        let newcomer = SecretKey::generate();
        let packet = signed_packet_at(&newcomer, now, "newcomer");
        assert_eq!(store.upsert(packet).await.expect("newcomer"), Upsert::Full);
        assert!(
            store
                .get(&endpoint_key(&newcomer))
                .await
                .expect("get")
                .is_none()
        );
        assert_eq!(metrics.store_packets.get(), 3);

        // Every stored endpoint is still answered.
        for endpoint in &endpoints {
            let stored = store.get(&endpoint_key(endpoint)).await.expect("get");
            assert!(stored.is_some());
        }
    }

    #[tokio::test]
    async fn a_store_at_its_ceiling_takes_new_endpoints_again_once_eviction_made_room() {
        let (store, metrics) = ceiling_store(3);
        let now = Timestamp::now().as_micros();
        let stale = [SecretKey::generate(), SecretKey::generate()];
        let honest = SecretKey::generate();
        for endpoint in &stale {
            let packet = signed_packet_at(endpoint, now - 2 * DAY_MICROS, "stale");
            assert_eq!(store.upsert(packet).await.expect("upsert"), Upsert::Stored);
        }
        let packet = signed_packet_at(&honest, now, "honest");
        assert_eq!(store.upsert(packet).await.expect("upsert"), Upsert::Stored);

        // The stale records are not evicted to make room: the new endpoint waits.
        let first = SecretKey::generate();
        let packet = signed_packet_at(&first, now, "first");
        assert_eq!(
            store.upsert(packet.clone()).await.expect("upsert"),
            Upsert::Full
        );
        for endpoint in stale.iter().chain([&honest]) {
            let stored = store.get(&endpoint_key(endpoint)).await.expect("get");
            assert!(stored.is_some(), "a refusal removed a stored packet");
        }
        assert_eq!(metrics.store_packets.get(), 3);

        // Eviction goes on at the ceiling and frees the room of the two it removes.
        store.evict_expired().await.expect("eviction");
        assert_eq!(metrics.store_packets.get(), 1);
        assert!(
            store
                .get(&endpoint_key(&honest))
                .await
                .expect("get")
                .is_some()
        );
        assert_eq!(store.upsert(packet).await.expect("upsert"), Upsert::Stored);
        let second = SecretKey::generate();
        let packet = signed_packet_at(&second, now, "second");
        assert_eq!(
            store.upsert(packet.clone()).await.expect("upsert"),
            Upsert::Stored
        );
        // Room for exactly what eviction freed.
        let third = SecretKey::generate();
        let packet = signed_packet_at(&third, now, "third");
        assert_eq!(store.upsert(packet).await.expect("upsert"), Upsert::Full);
        assert_eq!(metrics.store_packets.get(), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_count_and_the_ceiling_hold_after_a_restart() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("packets.db");
        let now = Timestamp::now().as_micros();
        let options = |max_packets| Options {
            max_packets,
            eviction_interval: Duration::from_secs(3600),
            ..Options::default()
        };
        let endpoints: Vec<_> = (0..3).map(|_| SecretKey::generate()).collect();
        {
            let metrics = Arc::new(Metrics::default());
            let store =
                SignedPacketStore::persistent(&path, options(3), metrics.clone(), no_hook())
                    .expect("a store");
            for endpoint in &endpoints[..2] {
                let packet = signed_packet_at(endpoint, now, "before");
                assert_eq!(store.upsert(packet).await.expect("upsert"), Upsert::Stored);
            }
            assert_eq!(metrics.store_packets.get(), 2);
        }

        // The count is read from the file at the start, with no packet published since.
        let metrics = Arc::new(Metrics::default());
        let store = SignedPacketStore::persistent(&path, options(3), metrics.clone(), no_hook())
            .expect("the store reopens");
        assert_eq!(metrics.store_packets.get(), 2);
        let packet = signed_packet_at(&endpoints[2], now, "after");
        assert_eq!(store.upsert(packet).await.expect("upsert"), Upsert::Stored);
        let extra = signed_packet_at(&SecretKey::generate(), now, "extra");
        assert_eq!(store.upsert(extra).await.expect("upsert"), Upsert::Full);
        drop(store);

        // A ceiling set below what the file holds removes nothing and refuses what is new.
        let metrics = Arc::new(Metrics::default());
        let store = SignedPacketStore::persistent(&path, options(1), metrics.clone(), no_hook())
            .expect("the store reopens");
        assert_eq!(metrics.store_packets.get(), 3);
        for endpoint in &endpoints {
            let stored = store.get(&endpoint_key(endpoint)).await.expect("get");
            assert!(stored.is_some());
        }
        let replacement = signed_packet_at(&endpoints[0], now + 1, "replaced");
        assert_eq!(
            store.upsert(replacement).await.expect("upsert"),
            Upsert::Stored
        );
        let extra = signed_packet_at(&SecretKey::generate(), now, "extra");
        assert_eq!(store.upsert(extra).await.expect("upsert"), Upsert::Full);
    }

    /// A store over `disk`, whose database is opened again at most once in each `pause`.
    fn disk_store(
        disk: &FullDisk,
        batch: usize,
        max_packets: usize,
        pause: Duration,
        hook: OnChange,
    ) -> (SignedPacketStore, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::default());
        let store = SignedPacketStore::with_backend(
            disk.clone(),
            Options {
                max_batch_size: batch,
                max_batch_time: Duration::from_secs(3600),
                eviction: Duration::from_secs(24 * 3600),
                max_packets,
                reopen_pause: pause,
                ..Options::default()
            },
            metrics.clone(),
            hook,
            false,
        )
        .expect("a store over the disk");
        (store, metrics)
    }

    /// Wait until the writer has dealt with everything sent before this: it takes messages in
    /// order, so an answer (or a refusal) to this one comes after the failure, the rollback and
    /// the cache's notice that an earlier batch led to. A disk that is set healthy before that
    /// would let the batch commit.
    async fn barrier(store: &SignedPacketStore) {
        let _ = store.get(&endpoint_key(&SecretKey::generate())).await;
    }

    /// Wait until the writer answers a read again. The database opens again on a thread of its
    /// own, so the requests after a failure are refused until it has: the wait ends on that, and
    /// its limit is one that only a hang reaches.
    async fn recovered(store: &SignedPacketStore) {
        tokio::time::timeout(Duration::from_secs(60), async {
            while store
                .get(&endpoint_key(&SecretKey::generate()))
                .await
                .is_err()
            {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the store did not recover");
    }

    fn packet_for(endpoint: &SecretKey, micros: u64) -> SignedPacket {
        signed_packet_at(endpoint, micros, "relay")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_disk_does_not_end_the_writer_and_the_store_serves_again_when_space_returns() {
        let disk = FullDisk::default();
        let (store, metrics) = disk_store(&disk, 1, 10, Duration::ZERO, no_hook());
        let now = Timestamp::now().as_micros();
        let (kept, stale) = (SecretKey::generate(), SecretKey::generate());
        for (endpoint, signed) in [(&kept, now), (&stale, now - 2 * DAY_MICROS)] {
            let packet = packet_for(endpoint, signed);
            assert_eq!(store.upsert(packet).await.expect("upsert"), Upsert::Stored);
        }

        disk.set(Disk::NoNewBlocks);
        for _ in 0..3 {
            // The first of these is answered before its batch commits and then lost with it; the
            // rest are refused. Either way the writer is there to take the next.
            let _ = store.upsert(packet_for(&SecretKey::generate(), now)).await;
        }
        assert!(metrics.store_failures.get() >= 1);
        disk.set(Disk::Healthy);
        recovered(&store).await;

        // Without a restart: reads, eviction and publication work, and none of what was
        // published while the disk was full is there.
        let stored = store.get(&endpoint_key(&kept)).await;
        assert!(stored.expect("the writer answers").is_some());
        store.evict_expired().await.expect("eviction goes on");
        assert!(
            store
                .get(&endpoint_key(&stale))
                .await
                .expect("get")
                .is_none()
        );
        let fresh = packet_for(&SecretKey::generate(), now);
        assert_eq!(store.upsert(fresh).await.expect("upsert"), Upsert::Stored);
        assert_eq!(metrics.store_packets.get(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_publication_that_meets_a_failing_write_is_refused_and_stores_nothing() {
        let disk = FullDisk::default();
        let (store, metrics) = disk_store(&disk, 1, 1_000_000, Duration::ZERO, no_hook());
        let now = Timestamp::now().as_micros();

        // Publish until the database file has to grow, which the disk refuses.
        disk.set(Disk::NoGrowth);
        let mut stored = Vec::new();
        let mut refused = None;
        for _ in 0..50_000 {
            let endpoint = SecretKey::generate();
            match store.upsert(packet_for(&endpoint, now)).await {
                Ok(outcome) => {
                    assert_eq!(outcome, Upsert::Stored);
                    stored.push(endpoint);
                }
                Err(_) => {
                    refused = Some(endpoint);
                    break;
                }
            }
        }
        let refused = refused.expect("the file never needed to grow");
        disk.set(Disk::Healthy);
        recovered(&store).await;

        // The refused publication was not stored and the cache was not told of it; the writer
        // goes on, and the count is what the store holds.
        let held = store.get(&endpoint_key(&refused)).await;
        assert!(held.expect("the writer answers").is_none());
        // Some publications were answered before the commit that failed, and lost with it. The
        // count is what the store holds, and not what was answered.
        let mut present = 0;
        for endpoint in &stored {
            if store
                .get(&endpoint_key(endpoint))
                .await
                .expect("get")
                .is_some()
            {
                present += 1;
            }
        }
        assert!(present > 0);
        assert_eq!(metrics.store_packets.get(), present);
        assert!(metrics.store_failures.get() >= 1);
        let again = store.upsert(packet_for(&refused, now)).await;
        assert_eq!(again.expect("upsert"), Upsert::Stored);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_publication_after_a_failed_commit_is_answered_only_once_it_is_committed() {
        let disk = FullDisk::default();
        let (store, _) = disk_store(&disk, 2, 10, Duration::ZERO, no_hook());
        let now = Timestamp::now().as_micros();

        // A batch that fails at its commit: both its publications were answered before it, and
        // are lost with it.
        let first = store.upsert(packet_for(&SecretKey::generate(), now)).await;
        assert_eq!(first.expect("upsert"), Upsert::Stored);
        disk.set(Disk::NoWrites);
        let second = store.upsert(packet_for(&SecretKey::generate(), now)).await;
        assert_eq!(second.expect("upsert"), Upsert::Stored);

        // Every publication after it waits for its own commit, which the failing disk refuses,
        // so none is answered and lost.
        for _ in 0..3 {
            let result = store.upsert(packet_for(&SecretKey::generate(), now)).await;
            assert!(result.is_err(), "a lost publication was answered");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_batch_that_fails_is_rolled_back_with_its_count_and_the_cache_is_told() {
        let disk = FullDisk::default();
        let (hook, calls) = recording_hook();
        let (store, metrics) = disk_store(&disk, 2, 4, Duration::ZERO, hook);
        let now = Timestamp::now().as_micros();
        let endpoints: Vec<_> = (0..4).map(|_| SecretKey::generate()).collect();

        // A batch of two that commits.
        for endpoint in &endpoints[..2] {
            let stored = store.upsert(packet_for(endpoint, now)).await;
            assert_eq!(stored.expect("upsert"), Upsert::Stored);
        }
        // A batch of two that meets the failing disk when it commits: the answer to the first
        // shows the batch was open and working, and the disk fails after it.
        let stored = store.upsert(packet_for(&endpoints[2], now)).await;
        assert_eq!(stored.expect("upsert"), Upsert::Stored);
        disk.set(Disk::NoWrites);
        let stored = store.upsert(packet_for(&endpoints[3], now)).await;
        assert_eq!(stored.expect("upsert"), Upsert::Stored);
        barrier(&store).await;
        // The count shows the commit and not the batch that was rolled back, whether or not the
        // database has opened again.
        assert_eq!(metrics.store_packets.get(), 2);
        disk.set(Disk::Healthy);
        recovered(&store).await;

        // The store holds what was committed, the count says so, and the ceiling counts the same.
        for (endpoint, held) in endpoints.iter().zip([true, true, false, false]) {
            let stored = store.get(&endpoint_key(endpoint)).await.expect("get");
            assert_eq!(stored.is_some(), held);
        }
        assert_eq!(metrics.store_packets.get(), 2);
        assert_eq!(metrics.store_failures.get(), 1);
        // Two held, so a ceiling of four takes two more and then refuses.
        for _ in 0..2 {
            let more = packet_for(&SecretKey::generate(), now);
            assert_eq!(store.upsert(more).await.expect("upsert"), Upsert::Stored);
        }
        let last = packet_for(&SecretKey::generate(), now);
        assert_eq!(store.upsert(last).await.expect("upsert"), Upsert::Full);

        // The writer told the cache about the two packets it applied and then rolled back, so
        // the cache cannot answer for a packet the store lost.
        let called = calls.lock().expect("calls").clone();
        let keys: Vec<_> = endpoints.iter().map(endpoint_key).collect();
        assert_eq!(called[..4], keys[..]);
        assert_eq!(called[4..6], keys[2..]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failures_in_a_row_open_the_database_again_at_most_once_in_each_pause() {
        let disk = FullDisk::default();
        let (store, metrics) = disk_store(&disk, 1, 10, Duration::from_secs(3600), no_hook());
        let now = Timestamp::now().as_micros();

        disk.set(Disk::NoWrites);
        // The first is answered before its commit fails. The rest are refused.
        let _ = store.upsert(packet_for(&SecretKey::generate(), now)).await;
        for _ in 0..20 {
            let result = store.upsert(packet_for(&SecretKey::generate(), now)).await;
            assert!(
                result.is_err(),
                "a publication was answered with the disk failing"
            );
        }

        // One attempt, made by the first failure. The rest were refused without a try, and
        // without a failure counted for each: nothing spins.
        assert_eq!(metrics.store_reopens.get(), 1);
        assert!(metrics.store_failures.get() <= 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_first_commit_after_failures_takes_the_writer_back_to_its_batches() {
        let disk = FullDisk::default();
        let (store, _) = disk_store(&disk, 2, 10, Duration::ZERO, no_hook());
        let now = Timestamp::now().as_micros();

        // A batch that fails at its commit.
        let _ = store.upsert(packet_for(&SecretKey::generate(), now)).await;
        disk.set(Disk::NoWrites);
        let _ = store.upsert(packet_for(&SecretKey::generate(), now)).await;
        barrier(&store).await;
        disk.set(Disk::Healthy);
        recovered(&store).await;

        // While the writer is failing a publication is committed, and the database synced,
        // before it is answered.
        let before = disk.syncs();
        let first = store.upsert(packet_for(&SecretKey::generate(), now)).await;
        assert_eq!(first.expect("upsert"), Upsert::Stored);
        assert!(disk.syncs() > before, "the answer came before the commit");

        // That commit ended the failure: the next publication is answered while its batch of two
        // is still open.
        let syncs = disk.syncs();
        let next = store.upsert(packet_for(&SecretKey::generate(), now)).await;
        assert_eq!(next.expect("upsert"), Upsert::Stored);
        assert_eq!(disk.syncs(), syncs, "the batch committed with one packet");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_eviction_pass_is_followed_by_one_that_removes_the_stale_packet() {
        let disk = FullDisk::default();
        let (store, metrics) = disk_store(&disk, 1, 10, Duration::ZERO, no_hook());
        let stale = SecretKey::generate();
        let packet = packet_for(&stale, Timestamp::now().as_micros() - 2 * DAY_MICROS);
        assert_eq!(store.upsert(packet).await.expect("upsert"), Upsert::Stored);

        // A pass over a failing disk does not remove it, and does not end the writer.
        disk.set(Disk::NoWrites);
        let _ = store.evict_expired().await;
        assert!(metrics.store_failures.get() >= 1);
        disk.set(Disk::Healthy);
        recovered(&store).await;

        store.evict_expired().await.expect("the next pass runs");
        assert!(
            store
                .get(&endpoint_key(&stale))
                .await
                .expect("get")
                .is_none()
        );
        assert_eq!(metrics.store_packets.get(), 0);
    }

    #[tokio::test]
    async fn the_eviction_loop_goes_on_after_a_pass_that_fails() {
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pass = {
            let runs = runs.clone();
            move || {
                let run = runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    match run < 3 {
                        true => Err(anyerr!("the writer refused the pass")),
                        false => Ok(()),
                    }
                }
            }
        };
        // The loop ends only when the writer is gone, which here is after six passes.
        let writer_gone = {
            let runs = runs.clone();
            move || runs.load(std::sync::atomic::Ordering::SeqCst) >= 6
        };

        evict_loop(pass, Duration::from_millis(1), writer_gone).await;

        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 6);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_commit_that_reaches_the_file_and_fails_to_sync_leaves_the_store_whole() {
        let disk = FullDisk::default();
        let (store, metrics) = disk_store(&disk, 2, 10, Duration::ZERO, no_hook());
        let now = Timestamp::now().as_micros();
        let endpoints: Vec<_> = (0..4).map(|_| SecretKey::generate()).collect();

        for endpoint in &endpoints[..3] {
            let stored = store.upsert(packet_for(endpoint, now)).await;
            assert_eq!(stored.expect("upsert"), Upsert::Stored);
        }
        // The third was the first of a batch of two, and the fourth completes it: the commit
        // writes its pages and fails at the sync.
        disk.set(Disk::NoSync);
        let stored = store.upsert(packet_for(&endpoints[3], now)).await;
        assert_eq!(stored.expect("upsert"), Upsert::Stored);
        barrier(&store).await;
        disk.set(Disk::Healthy);
        recovered(&store).await;

        // The commit failed, and the two packets committed before it are still there.
        assert!(metrics.store_failures.get() >= 1, "no commit failed");
        let mut held = Vec::new();
        for endpoint in &endpoints {
            let stored = store.get(&endpoint_key(endpoint)).await.expect("get");
            held.push(stored.is_some());
        }
        assert_eq!(held[..2], [true, true], "a packet committed before is lost");
        // The batch is in the file or it is not, and the count says which: a commit that failed at
        // its end may still be there once the database is read again, the whole batch or none of
        // it.
        assert_eq!(held[2], held[3], "half a batch is in the store");
        let present = held.iter().filter(|is_held| **is_held).count() as i64;
        assert_eq!(metrics.store_packets.get(), present);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reopen_that_takes_long_does_not_hold_the_writer() {
        // The database opens again only when the test lets it.
        let (release, held) = std::sync::mpsc::channel::<()>();
        let held = std::sync::Mutex::new(held);
        let disk = FullDisk::default();
        let again = disk.clone();
        let reopen: Reopen = Arc::new(move || {
            held.lock().expect("gate").recv().ok();
            Database::builder()
                .create_with_backend(again.clone())
                .anyerr()
        });
        let metrics = Arc::new(Metrics::default());
        let store = SignedPacketStore::with_backend_and_reopen(
            disk.clone(),
            Options {
                max_batch_size: 1,
                max_batch_time: Duration::from_secs(3600),
                reopen_pause: Duration::ZERO,
                ..Options::default()
            },
            metrics.clone(),
            no_hook(),
            false,
            reopen,
        )
        .expect("a store");
        // The sender is bound again after the store, so that it is dropped before the store is: with
        // it gone every held open goes at once, and a failing test does not wait for them.
        let release = release;
        let now = Timestamp::now().as_micros();
        let kept = SecretKey::generate();
        let stored = store.upsert(packet_for(&kept, now)).await;
        assert_eq!(stored.expect("upsert"), Upsert::Stored);

        // The commit of the first packet is done before the disk fails; then a commit fails, and
        // the open that follows is held. The publication that meets the failure and the request
        // after it stand inside the same limit as the checks below: a writer that waits for the
        // open fails the case on that limit and does not hang it.
        barrier(&store).await;
        disk.set(Disk::NoWrites);
        let limit = Duration::from_secs(30);
        let failure = async {
            let _ = store.upsert(packet_for(&SecretKey::generate(), now)).await;
            barrier(&store).await;
        };
        let answered = tokio::time::timeout(limit, failure).await;
        answered.expect("the writer did not answer while the open was held");

        // Every request is refused at once, and none waits for the open.
        for _ in 0..3 {
            let read = tokio::time::timeout(limit, store.get(&endpoint_key(&kept))).await;
            assert!(read.expect("a read waited for the open").is_err());
            let write = store.upsert(packet_for(&SecretKey::generate(), now));
            let write = tokio::time::timeout(limit, write).await;
            assert!(write.expect("a publication waited for the open").is_err());
        }
        assert_eq!(metrics.store_reopens.get(), 1, "a second open started");

        // The open ends, and the store answers what it holds.
        disk.set(Disk::Healthy);
        release.send(()).expect("gate");
        recovered(&store).await;
        let found = store.get(&endpoint_key(&kept)).await;
        assert!(found.expect("get").is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_pause_before_a_new_attempt_starts_when_an_attempt_ends() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // The first attempt is held for longer than the pause and then fails; a later one fails
        // at once.
        let (release, held) = std::sync::mpsc::channel::<()>();
        let held = std::sync::Mutex::new(held);
        let first = AtomicBool::new(true);
        let ended = Arc::new(AtomicBool::new(false));
        let attempt_ended = ended.clone();
        let reopen: Reopen = Arc::new(move || {
            if first.swap(false, Ordering::SeqCst) {
                held.lock().expect("gate").recv().ok();
            }
            attempt_ended.store(true, Ordering::SeqCst);
            Err(anyerr!("the database did not open"))
        });
        let disk = FullDisk::default();
        let pause = Duration::from_secs(3);
        let metrics = Arc::new(Metrics::default());
        let store = SignedPacketStore::with_backend_and_reopen(
            disk.clone(),
            Options {
                max_batch_size: 1,
                max_batch_time: Duration::from_secs(3600),
                reopen_pause: pause,
                ..Options::default()
            },
            metrics.clone(),
            no_hook(),
            false,
            reopen,
        )
        .expect("a store");
        // The sender is bound again after the store, so that it is dropped before the store is: with
        // it gone every held open goes at once, and a failing test does not wait for them.
        let release = release;
        let now = Timestamp::now().as_micros();

        // A commit fails, and the attempt that follows is held. The writer answers meanwhile.
        disk.set(Disk::NoWrites);
        let failure = async {
            let _ = store.upsert(packet_for(&SecretKey::generate(), now)).await;
            barrier(&store).await;
        };
        let answered = tokio::time::timeout(Duration::from_secs(30), failure).await;
        answered.expect("the writer did not answer while the open was held");
        assert_eq!(metrics.store_reopens.get(), 1);

        // The attempt has now lasted as long as the pause, and then it ends without a database.
        tokio::time::sleep(pause).await;
        release.send(()).expect("gate");
        tokio::time::timeout(Duration::from_secs(60), async {
            while !ended.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the attempt did not end");

        // The pause runs from the end of the attempt, so the requests that follow it start no new
        // one. A pause that ran from the start of the attempt would be over by now.
        for _ in 0..100 {
            let read = store.get(&endpoint_key(&SecretKey::generate())).await;
            assert!(read.is_err(), "a request was served without a database");
        }
        assert_eq!(
            metrics.store_reopens.get(),
            1,
            "an attempt started inside the pause after the last one ended"
        );
    }
}
