//! The RNP1 pipe driver (RNL1 §6; Nearby design step 5.5). One task per
//! pipe that came UP owns its pure [`PipeState`] and bridges the radio's
//! frames to the pipe's two byte channels. Each channel instance is a
//! [`tokio::io::duplex`] pair: the driver keeps one end, the Raven link gets
//! the other (the dial on this side's own channel, the contact-gated
//! responder on the other side's). No custom AsyncRead or AsyncWrite.
//!
//! - **Own channel** ([`Pipe::open_channel`]): channel 0 for the central, 1
//!   for the peripheral. A new instance opens only after both directions of
//!   the previous one FINed; until then the request waits (a request whose
//!   caller gave up is skipped).
//! - **The other side's channel:** its OPEN hands the new instance's end to
//!   the [`OnInbound`] callback.
//! - **Sending:** the driver reads at most `max_tx - 4` bytes from a channel
//!   only while that channel holds DATA credit and no frame waits for the
//!   radio. A [`Sent::WouldBlock`] holds that frame, and every later one,
//!   until [`Pipe::writable`]. So a stalled radio or a peer whose reader
//!   stopped stops the reads, the duplex buffer fills, and the link's write
//!   awaits.
//! - **Receiving:** DATA is written into the channel's end as the app reads
//!   it, and CREDIT goes back only for frames written
//!   ([`PipeState::consumed`]): a reader that stops holds at most the
//!   frames the other side may still send ([`W0`] with the reference
//!   granting) plus the duplex buffer. Once the app's end is gone, received
//!   bytes are dropped and still credited, so the other side can finish and
//!   FIN.
//! - **FIN:** the app shutting down (or dropping) its end FINs this side's
//!   direction; the other side's FIN ends the app's reads once every byte
//!   before it was delivered.
//! - **End:** a decode or state error (RESET with its code), a RESET from
//!   the other side, [`Pipe::reset`], [`Pipe::down`], a radio refusing a
//!   frame, every handle dropped (RESET SHUTDOWN), or no open channel for
//!   [`PIPE_IDLE`] (RESET IDLE). Every channel's driver end is dropped at
//!   once: the app's writes fail (broken pipe) and a read in the middle of a
//!   message fails (unexpected end). After a RESET either way the central
//!   disconnects. RNP1 does no retransmission: the dial fails and the outbox
//!   retries the exact bytes.
//!
//! Driver-held bytes (frames received but not yet read, frames waiting for
//! the radio) are counted ([`Pipe::buffered`]); with the duplex buffers they
//! stay within RNL1 §8's `2 x 64 x 512 B` per pipe.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use raven_core::nearby_link::{Frame, PipeError, PipeState, Role, RxAction, W0};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::radio::Sent;

/// No open channel for this long: RESET IDLE (RNL1 §6 timers).
pub(crate) const PIPE_IDLE: Duration = Duration::from_secs(30);
/// Received frames waiting for the driver. A legal peer stays far below
/// (its DATA is bounded by credit); one more resets the pipe with LIMIT.
pub(crate) const RX_QUEUE: usize = 256;
/// How long an ending pipe waits for the radio to take its RESET.
const RESET_GRACE: Duration = Duration::from_secs(1);
const PIPE_DOWN: &str = "nearby pipe is down";

/// Where a pipe's frames go: one radio connection.
pub(crate) trait FrameSink: Send + 'static {
    /// One frame: [`Sent::Queued`], or [`Sent::WouldBlock`] (offer it again
    /// after the next [`Pipe::writable`]). An error ends the pipe.
    fn send(&mut self, frame: &[u8]) -> Result<Sent, String>;
    /// End the connection (the central, after a RESET).
    fn disconnect(&mut self);
}

/// Called with the other side's channel number and the new instance's end
/// when the other side OPENs its channel. It must not wait (the engine
/// spawns the responder).
pub(crate) type OnInbound = Box<dyn FnMut(u8, DuplexStream) + Send>;

enum Ctl {
    Open(oneshot::Sender<Result<DuplexStream, String>>),
    Writable,
    Reset(PipeError),
    Down,
}

#[derive(Default)]
struct Stats {
    buffered: AtomicUsize,
    peak: AtomicUsize,
}

/// Why a pipe ended (its task's result).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipeEnd {
    /// This side sent RESET with this code.
    ResetSent(PipeError),
    /// The other side sent RESET with this code.
    ResetReceived(u8),
    /// The radio connection ended ([`Pipe::down`]).
    Down,
    /// The radio refused a frame.
    LinkError,
}

/// A handle on one running pipe. Clones share it; the pipe ends (RESET
/// SHUTDOWN) when the last one is dropped.
#[derive(Clone)]
pub(crate) struct Pipe {
    peer: [u8; 32],
    role: Role,
    rx: mpsc::Sender<Vec<u8>>,
    ctl: mpsc::UnboundedSender<Ctl>,
    /// Read by the tests' [`Pipe::buffered`]; the driver keeps its own.
    #[cfg(test)]
    stats: Arc<Stats>,
}

impl Pipe {
    /// Start the driver of a pipe that just came UP with `peer`: this
    /// side's `role`, its frame limits (`max_tx` this side sends, `max_rx`
    /// it receives), the connection's `sink`, and `on_inbound` for the other
    /// side's channel. Under 64 bytes either way there is no pipe
    /// ([`PipeError::Mtu`]).
    pub(crate) fn start(
        peer: [u8; 32],
        role: Role,
        max_tx: usize,
        max_rx: usize,
        sink: Box<dyn FrameSink>,
        on_inbound: OnInbound,
    ) -> Result<(Self, JoinHandle<PipeEnd>), PipeError> {
        let state = PipeState::new(role, max_tx, max_rx)?;
        let (rx_tx, rx_rx) = mpsc::channel(RX_QUEUE);
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let stats = Arc::new(Stats::default());
        let driver = Driver::new(state, sink, on_inbound, Arc::clone(&stats));
        let task = tokio::spawn(driver.run(rx_rx, ctl_rx));
        let pipe = Self {
            peer,
            role,
            rx: rx_tx,
            ctl: ctl_tx,
            #[cfg(test)]
            stats,
        };
        Ok((pipe, task))
    }

    pub(crate) fn peer(&self) -> [u8; 32] {
        self.peer
    }

    pub(crate) fn role(&self) -> Role {
        self.role
    }

    /// The driver still runs.
    pub(crate) fn is_up(&self) -> bool {
        !self.ctl.is_closed()
    }

    /// A new instance of this side's own channel (0 for the central, 1 for
    /// the peripheral), once the previous one FINed both ways. Dropping the
    /// stream FINs it.
    pub(crate) async fn open_channel(&self) -> Result<DuplexStream, String> {
        let (tx, rx) = oneshot::channel();
        self.ctl
            .send(Ctl::Open(tx))
            .map_err(|_| PIPE_DOWN.to_string())?;
        rx.await.map_err(|_| PIPE_DOWN.to_string())?
    }

    /// One frame the radio received on this pipe's connection. Never
    /// waits: a full queue resets the pipe with LIMIT.
    pub(crate) fn rx(&self, frame: Vec<u8>) -> Result<(), PipeError> {
        match self.rx.try_send(frame) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.reset(PipeError::Limit);
                Err(PipeError::Limit)
            }
            Err(TrySendError::Closed(_)) => Err(PipeError::Shutdown),
        }
    }

    /// The radio has room again after a [`Sent::WouldBlock`].
    pub(crate) fn writable(&self) {
        let _ = self.ctl.send(Ctl::Writable);
    }

    /// End the pipe with RESET `e` (DUPLICATE, SHUTDOWN).
    pub(crate) fn reset(&self, e: PipeError) {
        let _ = self.ctl.send(Ctl::Reset(e));
    }

    /// The radio connection ended.
    pub(crate) fn down(&self) {
        let _ = self.ctl.send(Ctl::Down);
    }

    /// Bytes the driver holds now: received but not yet read, and waiting
    /// for the radio.
    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        self.stats.buffered.load(Ordering::Relaxed)
    }

    /// The most [`Pipe::buffered`] has been.
    #[cfg(test)]
    pub(crate) fn peak_buffered(&self) -> usize {
        self.stats.peak.load(Ordering::Relaxed)
    }
}

/// The driver's side of one channel instance.
struct Chan {
    /// The app's bytes to send; `None` once this side FINed.
    reader: Option<ReadHalf<DuplexStream>>,
    /// Received bytes go here; `None` once shut down after the other side's
    /// FIN, or once the app's end is gone.
    writer: Option<WriteHalf<DuplexStream>>,
    /// Received payloads not yet written to the app.
    rxq: VecDeque<Vec<u8>>,
    /// Bytes of `rxq.front()` already written.
    rx_off: usize,
    /// The other side FINed: shut the writer down once `rxq` is empty.
    rx_fin: bool,
    /// The driver holds this instance (until both directions FINed).
    live: bool,
    buf: Vec<u8>,
}

impl Chan {
    fn new(payload: usize) -> Self {
        Self {
            reader: None,
            writer: None,
            rxq: VecDeque::new(),
            rx_off: 0,
            rx_fin: false,
            live: false,
            buf: vec![0; payload],
        }
    }

    fn held(&self) -> usize {
        self.rxq.iter().map(Vec::len).sum::<usize>() - self.rx_off
    }
}

/// What woke the driver.
enum Ev {
    Rx(Option<Vec<u8>>),
    Ctl(Option<Ctl>),
    Read(u8, io::Result<usize>),
    Wrote(u8, io::Result<usize>),
    Idle,
}

struct Driver {
    state: PipeState,
    sink: Box<dyn FrameSink>,
    on_inbound: OnInbound,
    stats: Arc<Stats>,
    chans: [Chan; 2],
    /// Frames for the radio, in order; the front one got WouldBlock while
    /// `blocked`.
    outq: VecDeque<Vec<u8>>,
    blocked: bool,
    /// Own-channel requests waiting for the previous instance to end.
    waiting: VecDeque<oneshot::Sender<Result<DuplexStream, String>>>,
    /// Since when no channel is open.
    idle_since: Option<Instant>,
    duplex_cap: usize,
}

impl Driver {
    fn new(
        state: PipeState,
        sink: Box<dyn FrameSink>,
        on_inbound: OnInbound,
        stats: Arc<Stats>,
    ) -> Self {
        let payload = state.max_payload();
        let duplex_cap = usize::from(W0) * state.max_tx().max(state.max_rx());
        Self {
            state,
            sink,
            on_inbound,
            stats,
            chans: [Chan::new(payload), Chan::new(payload)],
            outq: VecDeque::new(),
            blocked: false,
            waiting: VecDeque::new(),
            idle_since: None,
            duplex_cap,
        }
    }

    async fn run(
        mut self,
        mut rx: mpsc::Receiver<Vec<u8>>,
        mut ctl: mpsc::UnboundedReceiver<Ctl>,
    ) -> PipeEnd {
        let end = loop {
            self.note_buffered();
            let idle = !self.state.any_open();
            let idle_at = if idle {
                *self.idle_since.get_or_insert_with(Instant::now) + PIPE_IDLE
            } else {
                self.idle_since = None;
                Instant::now() + PIPE_IDLE
            };
            let send = [self.may_read(0), self.may_read(1)];
            let deliver = [self.may_deliver(0), self.may_deliver(1)];
            let [c0, c1] = &mut self.chans;
            let ev = tokio::select! {
                f = rx.recv() => Ev::Rx(f),
                c = ctl.recv() => Ev::Ctl(c),
                r = read_from(c0.reader.as_mut(), &mut c0.buf), if send[0] => Ev::Read(0, r),
                r = read_from(c1.reader.as_mut(), &mut c1.buf), if send[1] => Ev::Read(1, r),
                r = write_to(c0.writer.as_mut(), unread(&c0.rxq, c0.rx_off)), if deliver[0] => Ev::Wrote(0, r),
                r = write_to(c1.writer.as_mut(), unread(&c1.rxq, c1.rx_off)), if deliver[1] => Ev::Wrote(1, r),
                () = tokio::time::sleep_until(idle_at), if idle => Ev::Idle,
            };
            let step = match ev {
                Ev::Rx(Some(f)) => self.on_rx(&f).await,
                Ev::Rx(None) | Ev::Ctl(None) => Err(PipeEnd::ResetSent(PipeError::Shutdown)),
                Ev::Ctl(Some(c)) => self.on_ctl(c),
                Ev::Read(chan, r) => self.on_read(chan, r),
                Ev::Wrote(chan, r) => self.on_wrote(chan, r).await,
                Ev::Idle => Err(PipeEnd::ResetSent(PipeError::Idle)),
            };
            if let Err(end) = step {
                break end;
            }
            self.retire();
            self.open_waiting();
            if let Err(end) = self.flush() {
                break end;
            }
        };
        self.finish(end, &mut ctl).await
    }

    /// This side may send DATA on `chan` now.
    fn may_read(&self, chan: u8) -> bool {
        self.chans[usize::from(chan)].reader.is_some()
            && self.outq.is_empty()
            && !self.blocked
            && self.state.can_send(chan)
    }

    fn may_deliver(&self, chan: u8) -> bool {
        let c = &self.chans[usize::from(chan)];
        c.writer.is_some() && !c.rxq.is_empty()
    }

    fn queue(&mut self, f: &Frame<'_>) {
        self.outq.push_back(f.to_vec());
    }

    /// Grant back `frames` received DATA frames of `chan` (RNL1 §6 credits).
    fn credit(&mut self, chan: u8, frames: usize) {
        let frames = u16::try_from(frames).unwrap_or(u16::MAX);
        if let Some(f) = self.state.consumed(chan, frames) {
            self.queue(&f);
        }
    }

    async fn on_rx(&mut self, bytes: &[u8]) -> Result<(), PipeEnd> {
        match self.state.on_rx_bytes(bytes) {
            Ok(RxAction::Deliver { chan, bytes }) => {
                let c = &mut self.chans[usize::from(chan)];
                if c.writer.is_some() {
                    c.rxq.push_back(bytes.to_vec());
                } else {
                    self.credit(chan, 1);
                }
            }
            Ok(RxAction::Opened { chan }) => {
                let app = self.start_chan(chan);
                (self.on_inbound)(chan, app);
            }
            Ok(RxAction::Fined { chan }) => {
                let c = &mut self.chans[usize::from(chan)];
                c.rx_fin = true;
                if c.rxq.is_empty() {
                    shut(&mut c.writer).await;
                }
            }
            Ok(RxAction::Credit { .. }) => {}
            Ok(RxAction::Reset(code)) => return Err(PipeEnd::ResetReceived(code)),
            Err(e) => return Err(PipeEnd::ResetSent(e)),
        }
        Ok(())
    }

    fn on_ctl(&mut self, c: Ctl) -> Result<(), PipeEnd> {
        match c {
            Ctl::Open(reply) => self.waiting.push_back(reply),
            Ctl::Writable => self.blocked = false,
            Ctl::Reset(e) => return Err(PipeEnd::ResetSent(e)),
            Ctl::Down => return Err(PipeEnd::Down),
        }
        Ok(())
    }

    fn on_read(&mut self, chan: u8, r: io::Result<usize>) -> Result<(), PipeEnd> {
        match r {
            Ok(n) if n > 0 => {
                // `may_read` held: one credit and a sequence number.
                let seq = self
                    .state
                    .on_tx_data(chan)
                    .ok_or(PipeEnd::ResetSent(PipeError::Protocol))?;
                let c = &self.chans[usize::from(chan)];
                let f = Frame::Data {
                    chan,
                    seq,
                    payload: &c.buf[..n],
                }
                .to_vec();
                self.outq.push_back(f);
            }
            // The app shut down or dropped its end: FIN this direction.
            _ => {
                self.chans[usize::from(chan)].reader = None;
                if let Some(f) = self.state.fin(chan) {
                    self.queue(&f);
                }
            }
        }
        Ok(())
    }

    async fn on_wrote(&mut self, chan: u8, r: io::Result<usize>) -> Result<(), PipeEnd> {
        let c = &mut self.chans[usize::from(chan)];
        match r {
            Ok(n) => {
                c.rx_off += n;
                if c.rxq.front().is_some_and(|f| c.rx_off >= f.len()) {
                    c.rxq.pop_front();
                    c.rx_off = 0;
                    if c.rxq.is_empty() && c.rx_fin {
                        shut(&mut c.writer).await;
                    }
                    self.credit(chan, 1);
                }
            }
            // The app's end is gone: drop what it would have read and grant
            // it back, so the other side can finish and FIN.
            Err(_) => {
                let frames = c.rxq.len();
                c.rxq.clear();
                c.rx_off = 0;
                c.writer = None;
                self.credit(chan, frames);
            }
        }
        Ok(())
    }

    /// A new instance of `chan` in the driver; the app's end is returned.
    fn start_chan(&mut self, chan: u8) -> DuplexStream {
        self.retire_chan(chan);
        let (mine, app) = tokio::io::duplex(self.duplex_cap);
        let (r, w) = tokio::io::split(mine);
        let c = &mut self.chans[usize::from(chan)];
        c.reader = Some(r);
        c.writer = Some(w);
        c.rxq.clear();
        c.rx_off = 0;
        c.rx_fin = false;
        c.live = true;
        app
    }

    /// Let go of every instance that FINed both ways.
    fn retire(&mut self) {
        for chan in 0..2 {
            if self.chans[usize::from(chan)].live && !self.state.is_open(chan) {
                self.retire_chan(chan);
            }
        }
    }

    /// Let go of `chan`'s instance. Both directions FINed, so only received
    /// bytes the app has not read yet may be left: a small task writes them
    /// and then ends the app's reads.
    fn retire_chan(&mut self, chan: u8) {
        let c = &mut self.chans[usize::from(chan)];
        if !c.live {
            return;
        }
        c.live = false;
        c.reader = None;
        c.rx_fin = false;
        let rest = std::mem::take(&mut c.rxq);
        let off = std::mem::take(&mut c.rx_off);
        if let Some(mut w) = c.writer.take() {
            tokio::spawn(async move {
                for (i, f) in rest.iter().enumerate() {
                    let from = if i == 0 { off } else { 0 };
                    if w.write_all(&f[from..]).await.is_err() {
                        return;
                    }
                }
                let _ = w.shutdown().await;
            });
        }
    }

    /// Open this side's channel for the first waiting request, once the
    /// previous instance ended.
    fn open_waiting(&mut self) {
        let own = self.state.role().own_chan();
        while let Some(reply) = self.waiting.pop_front() {
            if reply.is_closed() {
                continue;
            }
            if self.chans[usize::from(own)].live {
                self.waiting.push_front(reply);
                break;
            }
            let Some(f) = self.state.open() else {
                self.waiting.push_front(reply);
                break;
            };
            self.queue(&f);
            let app = self.start_chan(own);
            // A caller that gave up meanwhile drops the end, which FINs it.
            let _ = reply.send(Ok(app));
            break;
        }
    }

    /// Hand queued frames to the radio until it would block.
    fn flush(&mut self) -> Result<(), PipeEnd> {
        while !self.blocked {
            let Some(f) = self.outq.front() else { break };
            match self.sink.send(f) {
                Ok(Sent::Queued) => {
                    self.outq.pop_front();
                }
                Ok(Sent::WouldBlock) => self.blocked = true,
                Err(_) => return Err(PipeEnd::LinkError),
            }
        }
        Ok(())
    }

    fn note_buffered(&self) {
        let now = self.chans.iter().map(Chan::held).sum::<usize>()
            + self.outq.iter().map(Vec::len).sum::<usize>();
        self.stats.buffered.store(now, Ordering::Relaxed);
        self.stats.peak.fetch_max(now, Ordering::Relaxed);
    }

    /// End the pipe: drop every channel's end at once, send this side's
    /// RESET (waiting at most [`RESET_GRACE`] for the radio to take it), and
    /// as the central disconnect after a RESET either way.
    async fn finish(mut self, end: PipeEnd, ctl: &mut mpsc::UnboundedReceiver<Ctl>) -> PipeEnd {
        let payload = self.state.max_payload();
        self.chans = [Chan::new(payload), Chan::new(payload)];
        self.waiting.clear();
        if let PipeEnd::ResetSent(e) = end {
            self.outq.clear();
            let f = self.state.reset(e);
            self.queue(&f);
            let grace = tokio::time::sleep(RESET_GRACE);
            tokio::pin!(grace);
            while self.flush().is_ok() && !self.outq.is_empty() {
                tokio::select! {
                    c = ctl.recv() => match c {
                        Some(Ctl::Writable) => self.blocked = false,
                        Some(Ctl::Open(reply)) => {
                            let _ = reply.send(Err(PIPE_DOWN.to_string()));
                        }
                        Some(Ctl::Reset(_)) => {}
                        Some(Ctl::Down) | None => break,
                    },
                    () = &mut grace => break,
                }
            }
        }
        let after_reset = matches!(end, PipeEnd::ResetSent(_) | PipeEnd::ResetReceived(_));
        if (after_reset && self.state.role() == Role::Central) || end == PipeEnd::LinkError {
            self.sink.disconnect();
        }
        self.stats.buffered.store(0, Ordering::Relaxed);
        end
    }
}

/// The received bytes the app has not read yet, of the first frame in
/// `rxq` (`off` of it already written).
fn unread(rxq: &VecDeque<Vec<u8>>, off: usize) -> &[u8] {
    rxq.front().map_or(&[], |f| &f[off..])
}

/// Read from the channel's end; pending forever without one.
async fn read_from(r: Option<&mut ReadHalf<DuplexStream>>, buf: &mut [u8]) -> io::Result<usize> {
    match r {
        Some(r) => r.read(buf).await,
        None => std::future::pending().await,
    }
}

/// Write into the channel's end; pending forever without one.
async fn write_to(w: Option<&mut WriteHalf<DuplexStream>>, bytes: &[u8]) -> io::Result<usize> {
    match w {
        Some(w) => w.write(bytes).await,
        None => std::future::pending().await,
    }
}

/// End the app's reads (the other side FINed and every byte was written).
async fn shut(w: &mut Option<WriteHalf<DuplexStream>>) {
    if let Some(mut w) = w.take() {
        let _ = w.shutdown().await;
    }
}

#[cfg(test)]
mod tests;
