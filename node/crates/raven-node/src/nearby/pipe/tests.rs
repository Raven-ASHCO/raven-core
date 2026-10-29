//! Two pipe drivers back to back over an in-memory wire (paused time): each
//! side's frames reach the other side's [`Pipe::rx`] in order; a wire end
//! with `cap` frames in flight answers WouldBlock and later Writable; a
//! disconnect ends both sides' connection after the frames before it.

use std::sync::Mutex;

use raven_core::nearby_link::{decode, Frame, PipeError, Role, KIND_DATA, MAX_FRAME, W0, W_MAX};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

use super::*;

#[derive(Default)]
struct Log {
    /// Every frame the radio took, in order.
    frames: Vec<Vec<u8>>,
    would_block: usize,
    disconnects: usize,
}

#[derive(Default)]
struct Flow {
    in_flight: usize,
    want: bool,
}

struct WireEnd {
    tx: mpsc::UnboundedSender<Option<Vec<u8>>>,
    flow: Arc<Mutex<Flow>>,
    cap: usize,
    log: Arc<Mutex<Log>>,
}

impl FrameSink for WireEnd {
    fn send(&mut self, frame: &[u8]) -> Result<Sent, String> {
        let mut flow = self.flow.lock().unwrap();
        let mut log = self.log.lock().unwrap();
        if flow.in_flight >= self.cap {
            flow.want = true;
            log.would_block += 1;
            return Ok(Sent::WouldBlock);
        }
        flow.in_flight += 1;
        log.frames.push(frame.to_vec());
        self.tx
            .send(Some(frame.to_vec()))
            .map_err(|_| "wire gone".to_string())?;
        Ok(Sent::Queued)
    }

    fn disconnect(&mut self) {
        self.log.lock().unwrap().disconnects += 1;
        let _ = self.tx.send(None);
    }
}

/// One wire direction: `from`'s frames to `to`, after `delay` each.
async fn pump(
    mut rx: mpsc::UnboundedReceiver<Option<Vec<u8>>>,
    flow: Arc<Mutex<Flow>>,
    pipes: oneshot::Receiver<(Pipe, Pipe)>,
    delay: Duration,
) {
    let Ok((to, from)) = pipes.await else { return };
    while let Some(item) = rx.recv().await {
        let Some(frame) = item else {
            // A radio takes a moment to report a disconnect.
            sleep(Duration::from_millis(10)).await;
            to.down();
            from.down();
            return;
        };
        if !delay.is_zero() {
            sleep(delay).await;
        }
        let _ = to.rx(frame);
        let wake = {
            let mut flow = flow.lock().unwrap();
            flow.in_flight -= 1;
            std::mem::take(&mut flow.want)
        };
        if wake {
            from.writable();
        }
    }
}

struct Side {
    pipe: Pipe,
    task: JoinHandle<PipeEnd>,
    inbound: mpsc::UnboundedReceiver<(u8, DuplexStream)>,
    log: Arc<Mutex<Log>>,
}

impl Side {
    fn sent(&self) -> Vec<Vec<u8>> {
        self.log.lock().unwrap().frames.clone()
    }

    fn data_frames(&self) -> usize {
        self.sent().iter().filter(|f| f[0] == KIND_DATA).count()
    }

    /// How the pipe ended.
    async fn end(&mut self) -> PipeEnd {
        (&mut self.task).await.unwrap()
    }

    async fn accept(&mut self) -> (u8, DuplexStream) {
        self.inbound.recv().await.expect("an inbound channel")
    }
}

/// A central and a peripheral pipe, wired back to back: `max_tx_c` is the
/// central's frame limit (the peripheral's `max_rx`) and `max_tx_p` the
/// peripheral's.
fn pair(max_tx_c: usize, max_tx_p: usize, cap: usize, delay: Duration) -> (Side, Side) {
    let side = |role: Role, max_tx: usize, max_rx: usize| {
        let (tx, rx) = mpsc::unbounded_channel();
        let flow = Arc::new(Mutex::new(Flow::default()));
        let log = Arc::new(Mutex::new(Log::default()));
        let sink = WireEnd {
            tx,
            flow: flow.clone(),
            cap,
            log: log.clone(),
        };
        let (in_tx, inbound) = mpsc::unbounded_channel();
        let peer = if role == Role::Central {
            [2; 32]
        } else {
            [1; 32]
        };
        let (pipe, task) = Pipe::start(
            peer,
            role,
            max_tx,
            max_rx,
            Box::new(sink),
            Box::new(move |chan, s| {
                let _ = in_tx.send((chan, s));
            }),
        )
        .expect("a pipe");
        let (go, wait) = oneshot::channel();
        tokio::spawn(pump(rx, flow, wait, delay));
        (
            Side {
                pipe,
                task,
                inbound,
                log,
            },
            go,
        )
    };
    let (c, go_c) = side(Role::Central, max_tx_c, max_tx_p);
    let (p, go_p) = side(Role::Peripheral, max_tx_p, max_tx_c);
    let _ = go_c.send((p.pipe.clone(), c.pipe.clone()));
    let _ = go_p.send((c.pipe.clone(), p.pipe.clone()));
    (c, p)
}

/// A link-stream message as Raven writes it: u32be length || bytes.
fn link_message(len: usize, salt: u8) -> Vec<u8> {
    let mut m = (len as u32).to_be_bytes().to_vec();
    m.extend((0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt) ^ (i >> 8) as u8));
    m
}

/// Every frame a side sent fits its `max_tx` and decodes at that size.
fn assert_frames_fit(side: &Side, max_tx: usize) {
    let frames = side.sent();
    assert!(!frames.is_empty());
    for f in &frames {
        assert!(f.len() <= max_tx, "{} > {max_tx}", f.len());
        decode(f, max_tx).expect("a valid frame");
    }
}

/// RNL1 §6: a 64 KiB Noise message (the largest, 65535 bytes, with its
/// length prefix) crosses each way on the central's channel, at the
/// smallest frame size, the largest, and a mix.
#[tokio::test(start_paused = true)]
async fn a_64_kib_message_crosses_both_ways_at_max_tx_64_and_512() {
    for (max_c, max_p) in [(64, 64), (512, 512), (64, 512), (185, 64)] {
        let (c, mut p) = pair(max_c, max_p, 4, Duration::ZERO);
        let mut a = c.pipe.open_channel().await.unwrap();
        let (chan, mut b) = p.accept().await;
        assert_eq!(chan, 0, "the central's channel");
        let ask = link_message(65535, 1);
        let answer = link_message(65535, 2);
        let (ask2, answer2) = (ask.clone(), answer.clone());
        let dial = tokio::spawn(async move {
            a.write_all(&ask2).await.unwrap();
            let mut got = vec![0; answer2.len()];
            a.read_exact(&mut got).await.unwrap();
            got
        });
        let mut got = vec![0; ask.len()];
        b.read_exact(&mut got).await.unwrap();
        assert!(got == ask, "{max_c}/{max_p}: request intact");
        b.write_all(&answer).await.unwrap();
        assert!(
            dial.await.unwrap() == answer,
            "{max_c}/{max_p}: reply intact"
        );
        assert_frames_fit(&c, max_c);
        assert_frames_fit(&p, max_p);
        assert!(c.pipe.is_up() && p.pipe.is_up());
        let need = 65539usize.div_ceil(max_c - 4);
        assert!(c.data_frames() >= need, "{} < {need}", c.data_frames());
    }
}

/// Write `out` on `s` while reading `want` from it; whether it came intact.
async fn talk(s: DuplexStream, out: Vec<u8>, want: Vec<u8>) -> bool {
    let (mut r, mut w) = tokio::io::split(s);
    let writer = async move { w.write_all(&out).await.map(|()| w) };
    let reader = async move {
        let mut got = vec![0; want.len()];
        r.read_exact(&mut got).await.map(|_| got == want)
    };
    let (w, same) = tokio::join!(writer, reader);
    w.is_ok() && same.unwrap_or(false)
}

/// RNL1 §6: both channels carry bytes both ways at the same time, their
/// frames interleaved on the one connection.
#[tokio::test(start_paused = true)]
async fn interleaved_channels_carry_both_ways_at_once() {
    let (mut c, mut p) = pair(185, 185, 4, Duration::from_millis(1));
    let a0 = c.pipe.open_channel().await.unwrap();
    let b1 = p.pipe.open_channel().await.unwrap();
    let (chan, b0) = p.accept().await;
    assert_eq!(chan, 0);
    let (chan, a1) = c.accept().await;
    assert_eq!(chan, 1);
    // Every end writes its 20 KB while it reads the other end's: four
    // streams at once, two per channel.
    let mut talks = Vec::new();
    for (salt, (mine, theirs)) in [(a0, b0), (b1, a1)].into_iter().enumerate() {
        let out = link_message(20_000, salt as u8);
        let back = link_message(20_000, 100 + salt as u8);
        talks.push(tokio::spawn(talk(mine, out.clone(), back.clone())));
        talks.push(tokio::spawn(talk(theirs, back, out)));
    }
    for t in talks {
        assert!(t.await.unwrap(), "every stream intact");
    }
    // The central's DATA alternates between its two channels many times.
    let chans: Vec<u8> = c
        .sent()
        .iter()
        .filter(|f| f[0] == KIND_DATA)
        .map(|f| f[1])
        .collect();
    let switches = chans.windows(2).filter(|w| w[0] != w[1]).count();
    assert!(switches > 10, "interleaved: {switches} switches");
}

/// RNL1 §6 credits and §8 buffering: a reader that stops stalls the sender
/// at the frames its credit allows; the receiving driver holds at most
/// those frames (within the per-pipe cap); reading again resumes it.
#[tokio::test(start_paused = true)]
async fn credit_stalls_the_sender_and_resumes_when_the_reader_reads() {
    let (c, mut p) = pair(512, 512, 64, Duration::ZERO);
    let mut a = c.pipe.open_channel().await.unwrap();
    let (_, mut b) = p.accept().await;
    let msg = link_message(65535, 3);
    let m = msg.clone();
    let writer = tokio::spawn(async move {
        a.write_all(&m).await.unwrap();
        a
    });
    sleep(Duration::from_secs(5)).await;
    let stalled = c.data_frames();
    sleep(Duration::from_secs(5)).await;
    assert_eq!(c.data_frames(), stalled, "no credit, no DATA");
    assert!(stalled < 65539 / 508, "{stalled} frames before the stall");
    assert!(!writer.is_finished(), "the link's write awaits");
    let max_rx = 512;
    assert!(
        p.pipe.buffered() <= usize::from(W0) * max_rx,
        "{} buffered",
        p.pipe.buffered()
    );
    assert!(p.pipe.buffered() > 0);
    let cap = 2 * usize::from(W_MAX) * MAX_FRAME;
    assert!(p.pipe.peak_buffered() <= usize::from(W0) * max_rx);
    assert!(c.pipe.peak_buffered() <= cap);
    let mut got = vec![0; msg.len()];
    b.read_exact(&mut got).await.unwrap();
    assert!(got == msg, "resumed and intact");
    let _a = writer.await.unwrap();
    assert!(p.pipe.peak_buffered() <= usize::from(W0) * max_rx);
}

/// A radio that answers WouldBlock gets the same frame again after
/// Writable, in order, nothing lost or repeated.
#[tokio::test(start_paused = true)]
async fn would_block_holds_the_frame_until_writable() {
    let (c, mut p) = pair(128, 128, 1, Duration::from_millis(2));
    let mut a = c.pipe.open_channel().await.unwrap();
    let (_, mut b) = p.accept().await;
    let ask = link_message(30_000, 4);
    let answer = link_message(30_000, 5);
    let (ask2, answer2) = (ask.clone(), answer.clone());
    let dial = tokio::spawn(async move {
        a.write_all(&ask2).await.unwrap();
        let mut got = vec![0; answer2.len()];
        a.read_exact(&mut got).await.unwrap();
        got == answer2
    });
    let mut got = vec![0; ask.len()];
    b.read_exact(&mut got).await.unwrap();
    assert!(got == ask);
    b.write_all(&answer).await.unwrap();
    assert!(dial.await.unwrap());
    for side in [&c, &p] {
        assert!(side.log.lock().unwrap().would_block > 0, "WouldBlock seen");
        let seqs: Vec<u16> = side
            .sent()
            .iter()
            .filter_map(|f| match decode(f, 128) {
                Ok(Frame::Data { seq, .. }) => Some(seq),
                _ => None,
            })
            .collect();
        assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "in order, once");
    }
}

/// RNL1 §6 timers: no open channel for 30 s is RESET IDLE; the central
/// disconnects.
#[tokio::test(start_paused = true)]
async fn an_idle_pipe_resets_after_30_s() {
    let (mut c, mut p) = pair(512, 512, 4, Duration::ZERO);
    sleep(Duration::from_secs(29)).await;
    assert!(c.pipe.is_up() && p.pipe.is_up());
    sleep(Duration::from_secs(2)).await;
    let (ce, pe) = (c.end().await, p.end().await);
    let idle = |e: PipeEnd| {
        matches!(
            e,
            PipeEnd::ResetSent(PipeError::Idle) | PipeEnd::ResetReceived(2) | PipeEnd::Down
        )
    };
    assert!(idle(ce) && idle(pe), "{ce:?} {pe:?}");
    // Both timers ran out at once: either side's RESET may come first.
    let reset_idle = vec![0x1F, 2];
    assert!(c.sent().contains(&reset_idle) || p.sent().contains(&reset_idle));
    assert_eq!(c.log.lock().unwrap().disconnects, 1);
    assert_eq!(p.log.lock().unwrap().disconnects, 0, "a peripheral cannot");
    assert!(!c.pipe.is_up() && !p.pipe.is_up());
}

/// An open channel keeps the pipe; once it FINed both ways the idle clock
/// starts.
#[tokio::test(start_paused = true)]
async fn an_open_channel_keeps_the_pipe_and_its_end_starts_the_idle_clock() {
    let (c, mut p) = pair(512, 512, 4, Duration::ZERO);
    let a = c.pipe.open_channel().await.unwrap();
    let (_, b) = p.accept().await;
    sleep(Duration::from_secs(60)).await;
    assert!(c.pipe.is_up() && p.pipe.is_up());
    drop(a);
    drop(b);
    sleep(Duration::from_secs(29)).await;
    assert!(c.pipe.is_up() && p.pipe.is_up());
    sleep(Duration::from_secs(2)).await;
    assert!(!c.pipe.is_up() && !p.pipe.is_up());
}

/// RNL1 §6: a RESET in the middle of a message fails both channel ends:
/// the dialer's write and the responder's read of the rest.
#[tokio::test(start_paused = true)]
async fn a_peer_reset_mid_message_errors_both_duplex_ends() {
    let (mut c, mut p) = pair(512, 512, 4, Duration::ZERO);
    let mut a = c.pipe.open_channel().await.unwrap();
    let (_, mut b) = p.accept().await;
    let msg = link_message(65535, 6);
    let writer = tokio::spawn(async move { a.write_all(&msg).await });
    let mut head = vec![0; 1000];
    b.read_exact(&mut head).await.unwrap();
    p.pipe.reset(PipeError::Shutdown);
    let mut rest = vec![0; 64_535];
    let err = b.read_exact(&mut rest).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    let err = writer.await.unwrap().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(p.end().await, PipeEnd::ResetSent(PipeError::Shutdown));
    assert_eq!(c.end().await, PipeEnd::ResetReceived(4));
    assert!(p.sent().contains(&vec![0x1F, 4]));
    assert_eq!(c.log.lock().unwrap().disconnects, 1, "the central");
    assert!(c.pipe.open_channel().await.is_err(), "the pipe is down");
}

/// RNL1 §6 channel instances: a new OPEN of the own channel waits until
/// both directions of the previous instance FINed.
#[tokio::test(start_paused = true)]
async fn the_own_channel_reopens_only_after_both_fins() {
    let (c, mut p) = pair(512, 512, 4, Duration::ZERO);
    let a1 = c.pipe.open_channel().await.unwrap();
    let (_, b1) = p.accept().await;
    let pipe = c.pipe.clone();
    let second = tokio::spawn(async move { pipe.open_channel().await });
    sleep(Duration::from_secs(1)).await;
    assert!(!second.is_finished(), "the first instance is open");
    drop(a1);
    sleep(Duration::from_secs(1)).await;
    assert!(!second.is_finished(), "only this side FINed");
    drop(b1);
    let mut a2 = second.await.unwrap().unwrap();
    let (chan, mut b2) = p.accept().await;
    assert_eq!(chan, 0);
    a2.write_all(b"again").await.unwrap();
    let mut got = [0; 5];
    b2.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"again");
    let opens = c.sent().iter().filter(|f| f[..] == [0x10, 0]).count();
    assert_eq!(opens, 2);
}

/// Bytes that arrived before both FINs still reach a reader that reads
/// late, then its read ends cleanly.
#[tokio::test(start_paused = true)]
async fn bytes_before_the_fins_reach_a_late_reader_then_eof() {
    let (c, mut p) = pair(512, 512, 4, Duration::ZERO);
    let mut a = c.pipe.open_channel().await.unwrap();
    let (_, mut b) = p.accept().await;
    let msg = link_message(6000, 7);
    a.write_all(&msg).await.unwrap();
    drop(a);
    sleep(Duration::from_secs(1)).await;
    b.shutdown().await.unwrap();
    sleep(Duration::from_secs(1)).await;
    let mut got = Vec::new();
    b.read_to_end(&mut got).await.unwrap();
    assert!(got == msg, "{} bytes", got.len());
    assert!(c.pipe.is_up() && p.pipe.is_up());
}

/// RNL1 §6 validity: a frame the pipe cannot accept is RESET with its
/// code; the central disconnects.
#[tokio::test(start_paused = true)]
async fn a_bad_frame_resets_with_its_code_and_the_central_disconnects() {
    let (mut c, mut p) = pair(512, 512, 4, Duration::ZERO);
    c.pipe.rx(vec![0x99]).unwrap();
    assert_eq!(c.end().await, PipeEnd::ResetSent(PipeError::Protocol));
    assert_eq!(c.sent().last(), Some(&vec![0x1F, 1]));
    assert_eq!(c.log.lock().unwrap().disconnects, 1);
    assert_eq!(p.end().await, PipeEnd::ResetReceived(1));
}

/// A sink that records and never blocks.
struct Recorder(Arc<Mutex<Log>>);

impl FrameSink for Recorder {
    fn send(&mut self, frame: &[u8]) -> Result<Sent, String> {
        self.0.lock().unwrap().frames.push(frame.to_vec());
        Ok(Sent::Queued)
    }

    fn disconnect(&mut self) {
        self.0.lock().unwrap().disconnects += 1;
    }
}

fn lone(role: Role) -> (Pipe, JoinHandle<PipeEnd>, Arc<Mutex<Log>>) {
    let log = Arc::new(Mutex::new(Log::default()));
    let (pipe, task) = Pipe::start(
        [3; 32],
        role,
        512,
        512,
        Box::new(Recorder(log.clone())),
        Box::new(|_, _| {}),
    )
    .unwrap();
    (pipe, task, log)
}

/// No pipe under 64 bytes a frame; the last handle dropped is RESET
/// SHUTDOWN; a full receive queue is RESET LIMIT; a peripheral never
/// disconnects.
#[tokio::test(start_paused = true)]
async fn pipe_limits_and_ends() {
    let sink = Box::new(Recorder(Arc::default()));
    assert!(matches!(
        Pipe::start([0; 32], Role::Central, 63, 512, sink, Box::new(|_, _| {})),
        Err(PipeError::Mtu)
    ));

    let (pipe, task, log) = lone(Role::Central);
    assert_eq!(pipe.peer(), [3; 32]);
    assert_eq!(pipe.role(), Role::Central);
    drop(pipe);
    assert_eq!(task.await.unwrap(), PipeEnd::ResetSent(PipeError::Shutdown));
    assert_eq!(log.lock().unwrap().frames, vec![vec![0x1F, 4]]);
    assert_eq!(log.lock().unwrap().disconnects, 1);

    let (pipe, task, log) = lone(Role::Peripheral);
    // The driver has not run yet (one thread): the queue fills.
    for _ in 0..RX_QUEUE {
        pipe.rx(vec![0x12, 1, 0, 4]).unwrap();
    }
    assert_eq!(pipe.rx(vec![0x12, 1, 0, 4]), Err(PipeError::Limit));
    assert!(matches!(task.await.unwrap(), PipeEnd::ResetSent(_)));
    let log = log.lock().unwrap();
    assert_eq!(log.frames.len(), 1);
    assert_eq!(log.frames[0][0], 0x1F);
    assert_eq!(log.disconnects, 0);
    assert_eq!(pipe.rx(vec![0x10, 0]), Err(PipeError::Shutdown));
}

/// The radio connection ending ends the pipe at once, without a frame.
#[tokio::test(start_paused = true)]
async fn down_ends_the_pipe_without_a_frame() {
    let (pipe, task, log) = lone(Role::Central);
    let stream = pipe.open_channel().await.unwrap();
    pipe.down();
    assert_eq!(task.await.unwrap(), PipeEnd::Down);
    {
        let log = log.lock().unwrap();
        assert_eq!(log.frames, vec![vec![0x10, 0]], "only the OPEN");
        assert_eq!(log.disconnects, 0);
    }
    let mut s = stream;
    assert_eq!(s.read(&mut [0; 8]).await.unwrap(), 0);
    assert!(s.write_all(b"x").await.is_err());
}
