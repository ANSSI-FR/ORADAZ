use crate::FL;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::writer::OradazWriter;

use log::error;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

/// Capacity of the writer actor's mpsc channel. Single source of truth so the
/// channel size and the [`WriterHandle::queue_usage_pct`] denominator cannot
/// drift apart (a drift would silently skew the reported queue-usage percentage).
pub(crate) const WRITER_CHANNEL_CAPACITY: usize = 8192;

/// Maximum bytes of data writes queued-or-in-flight in the writer actor at once.
/// The message-count cap alone (8192 × an unbounded per-message size) could buffer
/// well over a gigabyte on a large tenant; a byte-budget permit per data byte
/// bounds the transient memory deterministically. 256 MiB is generous yet bounded —
/// producers block in [`WriterHandle::write_file`] once it is exhausted, which
/// propagates backpressure up the pipeline (and via the AIMD window) rather than
/// growing memory. Log writes are exempt (they stay non-blocking, drop-on-full).
pub(crate) const WRITER_MEMORY_BUDGET_BYTES: usize = 256 * 1024 * 1024;

/// Count of log records dropped without being written: either by
/// [`WriterHandle::try_write_log`] because the writer channel was full, or by the
/// actor because the writer was already closed (finalized / marked broken).
/// Dropping is by design — logging stays non-blocking, and a closed writer can no
/// longer persist anything — and this counter lets the drop count be reported at
/// end-of-dump instead of being silent. Only `oradaz.log` completeness is
/// affected; collected data is not.
static DROPPED_LOG_COUNT: AtomicU64 = AtomicU64::new(0);

/// Number of log records dropped due to writer backpressure or a closed writer.
pub fn dropped_log_count() -> u64 {
    DROPPED_LOG_COUNT.load(Ordering::Relaxed)
}

/// Minimum wait on the byte-budget semaphore counted as a producer stall. Below
/// this, `acquire_many_owned` returned essentially immediately (budget available),
/// and counting it would drown the real stalls in microsecond-scale noise.
const WRITER_BUDGET_BLOCK_THRESHOLD: Duration = Duration::from_millis(1);

/// Peak writer-channel message saturation (`queue_usage_pct`, 0–100) over the run.
static PEAK_WRITER_QUEUE_PCT: AtomicU64 = AtomicU64::new(0);
/// Peak bytes of data writes queued-or-in-flight against the byte budget.
static PEAK_WRITER_INFLIGHT_BYTES: AtomicU64 = AtomicU64::new(0);
/// Total nanoseconds producers spent blocked on the byte budget in `write_file`
/// (only waits ≥ [`WRITER_BUDGET_BLOCK_THRESHOLD`]). The *direct* signal that
/// single-core MLA compression is the pipeline bottleneck: non-zero means
/// producers stalled because the writer could not keep up with data production.
static WRITER_BUDGET_BLOCKED_NANOS: AtomicU64 = AtomicU64::new(0);
/// Number of `write_file` calls that blocked ≥ [`WRITER_BUDGET_BLOCK_THRESHOLD`]
/// on the byte budget. Pairs with the total to tell one long stall from many short.
static WRITER_BUDGET_BLOCKED_COUNT: AtomicU64 = AtomicU64::new(0);

/// Peak writer-channel saturation percentage (0–100) observed over the run.
pub fn peak_writer_queue_pct() -> u64 {
    PEAK_WRITER_QUEUE_PCT.load(Ordering::Relaxed)
}
/// Peak bytes queued-or-in-flight against the writer byte budget over the run.
pub fn peak_writer_inflight_bytes() -> u64 {
    PEAK_WRITER_INFLIGHT_BYTES.load(Ordering::Relaxed)
}
/// Total nanoseconds producers spent blocked on the writer byte budget.
pub fn writer_budget_blocked_nanos() -> u64 {
    WRITER_BUDGET_BLOCKED_NANOS.load(Ordering::Relaxed)
}
/// Number of `write_file` calls that stalled on the writer byte budget.
pub fn writer_budget_blocked_count() -> u64 {
    WRITER_BUDGET_BLOCKED_COUNT.load(Ordering::Relaxed)
}

/// Messages that can be sent to the OradazWriter actor.
pub enum WriterMsg {
    /// Write a log entry.
    WriteLog(String),
    /// Write a file.
    WriteFile {
        folder: String,
        file: String,
        data: String,
        /// Byte-budget permit held for `data.len()` bytes; dropped by the actor
        /// after the write completes, returning the budget to blocked producers.
        _permit: OwnedSemaphorePermit,
    },
    /// Finalize the archive.
    Finalize(oneshot::Sender<Result<(), Error>>),
    /// Mark the archive as broken.
    SetBroken(oneshot::Sender<Result<(), Error>>),
    /// Get the final MLA path.
    GetFinalPath(oneshot::Sender<Option<String>>),
}

/// A handle to the OradazWriter actor.
#[derive(Clone)]
pub struct WriterHandle {
    sender: mpsc::Sender<WriterMsg>,
    /// Byte-budget semaphore for data-write backpressure (see
    /// [`WRITER_MEMORY_BUDGET_BYTES`]). `write_file` acquires `data.len()` permits
    /// before queueing; the actor releases them after the write.
    byte_budget: Arc<Semaphore>,
}

impl WriterHandle {
    /// Sends a log entry to be written (asynchronously).
    pub async fn write_log(&self, record: String) -> Result<(), Error> {
        self.sender
            .send(WriterMsg::WriteLog(record))
            .await
            .map_err(|_| Error::WriterLock)
    }

    /// Sends a log entry to be written (synchronously).
    /// If the channel is full, the log is dropped.
    pub fn try_write_log(&self, record: String) {
        if self.sender.try_send(WriterMsg::WriteLog(record)).is_err() {
            // Channel full: drop the log line (by design — keeps logging
            // non-blocking) but count it so the drop is surfaced at end-of-dump
            // instead of being completely silent.
            DROPPED_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Sends a file to be written.
    pub async fn write_file(
        &self,
        folder: String,
        file: String,
        data: String,
    ) -> Result<(), Error> {
        // Acquire byte-budget permits before queueing so the in-flight data bytes
        // stay bounded regardless of message size or count. A single write larger
        // than the whole budget takes the entire budget (serialised), so it can
        // never deadlock waiting for permits it can't get.
        let permits = data.len().min(WRITER_MEMORY_BUDGET_BYTES) as u32;
        // Time the acquire: a non-trivial wait means producers are blocking
        // because the single-core MLA compression cannot drain the budget fast
        // enough — the direct evidence of writer-bound throughput (see the
        // WRITER_BUDGET_BLOCKED_* observability counters).
        let wait_start = Instant::now();
        let permit = self
            .byte_budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| Error::WriterLock)?;
        let waited = wait_start.elapsed();
        if waited >= WRITER_BUDGET_BLOCK_THRESHOLD {
            WRITER_BUDGET_BLOCKED_NANOS.fetch_add(
                waited.as_nanos().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            WRITER_BUDGET_BLOCKED_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        // Record the byte-budget and channel-saturation peaks at this event site
        // (not from the 15s memory sample, which would miss sub-interval spikes).
        let inflight =
            WRITER_MEMORY_BUDGET_BYTES.saturating_sub(self.byte_budget.available_permits());
        PEAK_WRITER_INFLIGHT_BYTES.fetch_max(inflight as u64, Ordering::Relaxed);
        PEAK_WRITER_QUEUE_PCT.fetch_max(self.queue_usage_pct(), Ordering::Relaxed);
        self.sender
            .send(WriterMsg::WriteFile {
                folder,
                file,
                data,
                _permit: permit,
            })
            .await
            .map_err(|_| Error::WriterLock)
    }

    /// Finalizes the archive and waits for the result.
    pub async fn finalize(&self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(WriterMsg::Finalize(tx))
            .await
            .map_err(|_| Error::WriterLock)?;
        rx.await.map_err(|_| Error::WriterLock)?
    }

    /// Marks the archive as broken and waits for the result.
    pub async fn set_broken(&self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(WriterMsg::SetBroken(tx))
            .await
            .map_err(|_| Error::WriterLock)?;
        rx.await.map_err(|_| Error::WriterLock)?
    }

    /// Returns the current writer queue usage as a percentage (0–100).
    ///
    /// The writer actor channel has a fixed capacity ([`WRITER_CHANNEL_CAPACITY`]).
    /// A value > 0 means the actor is falling behind the write rate; surfaced in
    /// the progress UI.
    pub fn queue_usage_pct(&self) -> u64 {
        let used = WRITER_CHANNEL_CAPACITY.saturating_sub(self.sender.capacity());
        (used * 100 / WRITER_CHANNEL_CAPACITY) as u64
    }

    /// Returns the bytes of data writes currently queued-or-in-flight against the
    /// byte budget ([`WRITER_MEMORY_BUDGET_BYTES`]). A value approaching the budget
    /// means producers are about to block in [`WriterHandle::write_file`] — i.e.
    /// single-core MLA compression cannot keep up. Surfaced in the debug memory
    /// sample for after-the-fact diagnosis.
    pub fn byte_budget_inflight_bytes(&self) -> usize {
        WRITER_MEMORY_BUDGET_BYTES.saturating_sub(self.byte_budget.available_permits())
    }

    /// Returns the final `.mla` path.
    pub async fn final_mla_path(&self) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(WriterMsg::GetFinalPath(tx))
            .await
            .map_err(|_| Error::WriterLock)
            .ok()?;
        rx.await.ok().flatten()
    }
}

/// The background task that manages the OradazWriter.
pub async fn spawn_writer_task(
    config: Config,
    output: PathBuf,
    name: String,
) -> Result<(WriterHandle, tokio::task::JoinHandle<()>), Error> {
    let writer = OradazWriter::new(&config, &output, &name)?;
    let (tx, mut rx) = mpsc::channel::<WriterMsg>(WRITER_CHANNEL_CAPACITY);
    let byte_budget = Arc::new(Semaphore::new(WRITER_MEMORY_BUDGET_BYTES));

    let handle = tokio::spawn(async move {
        let mut writer = writer;
        let mut closed = false;
        // Set when a *data* file write fails. Writes are fire-and-forget (the
        // sender awaits only the enqueue, not the disk write), so the only
        // timing-safe point to act on an accumulated failure is `Finalize`: the
        // FIFO single-consumer channel guarantees every prior write has been
        // processed by then. A failed data write means the archive is incomplete,
        // so we refuse to finalize clean and report failure — the caller marks it
        // `.broken`, so a collection with missing data is reported as `.broken`
        // rather than COMPLETE. (Log-write failures are out of scope: a dropped log line is not a
        // data-integrity problem, and `try_write_log` already drops on a full
        // queue by design.)
        let mut data_write_failed = false;
        while let Some(msg) = rx.recv().await {
            match msg {
                WriterMsg::WriteLog(record) => {
                    if closed {
                        // The writer is finalized / marked broken: this log can no
                        // longer be persisted. Count the drop (rather than discard
                        // it silently) so it surfaces in the end-of-dump report. Rare
                        // in the normal flow (the logger is removed before close), but
                        // a concurrent task can still enqueue a WriteLog here.
                        DROPPED_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
                    } else if let Err(e) = writer.write_log(record) {
                        error!("{:FL$}Error writing log: {:?}", "WriterActor", e);
                    }
                }
                WriterMsg::WriteFile {
                    folder,
                    file,
                    data,
                    _permit,
                } => {
                    // MLA compression+encryption is synchronous: this call occupies
                    // a tokio worker thread for the duration of the write. This is a
                    // known, accepted trade-off — the byte-budget backpressure
                    // (WRITER_MEMORY_BUDGET_BYTES) bounds the queued data memory and
                    // `queue_usage_pct` surfaces message-count saturation.
                    if !closed && let Err(e) = writer.write_file(folder, file, data) {
                        data_write_failed = true;
                        error!("{:FL$}Error writing file: {:?}", "WriterActor", e);
                    }
                    // `_permit` drops here, returning its byte-budget to producers.
                }
                WriterMsg::Finalize(tx) => {
                    let res = if data_write_failed {
                        error!(
                            "{:FL$}One or more data files failed to write; the archive is incomplete and will be marked .broken",
                            "WriterActor"
                        );
                        Err(Error::WriteFile)
                    } else {
                        writer.finalize()
                    };
                    closed = true;
                    let _ = tx.send(res);
                }
                WriterMsg::SetBroken(tx) => {
                    let res = writer.set_broken();
                    closed = true;
                    let _ = tx.send(res);
                }
                WriterMsg::GetFinalPath(tx) => {
                    let res = writer.final_mla_path();
                    let _ = tx.send(res);
                }
            }
        }
    });

    Ok((
        WriterHandle {
            sender: tx,
            byte_budget,
        },
        handle,
    ))
}
