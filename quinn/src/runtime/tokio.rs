use std::{
    collections::VecDeque,
    future::Future,
    io::{self, IoSliceMut},
    mem,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Poll, Waker, ready},
    time::{Duration, Instant},
};

use tokio::{
    io::Interest,
    time::{Sleep, sleep_until},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPollHelper};

/// A Quinn runtime for Tokio
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(sleep_until(t.into()))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = Arc::new(udp::UdpSocketState::new((&sock).into())?);
        let on = |k: &str| std::env::var_os(k).is_some();
        let seal = on("QUINN_SEAL_THREAD");
        let send = match seal || on("QUINN_SEND_THREAD") {
            true => Some(SendThread::start(sock.try_clone()?, inner.clone())?),
            false => None,
        };
        let decrypt = on("QUINN_DECRYPT_THREAD");
        let recv = match decrypt || on("QUINN_RECV_THREAD") {
            true => Some(RecvThread::start(sock.try_clone()?, inner.clone(), decrypt)?),
            false => None,
        };
        Ok(Arc::new(UdpSocket {
            inner,
            io: tokio::net::UdpSocket::from_std(sock)?,
            send,
            seal,
            recv,
        }))
    }

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}

impl AsyncTimer for Sleep {
    fn reset(self: Pin<&mut Self>, t: Instant) {
        Self::reset(self, t.into())
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Future::poll(self, cx)
    }
}

#[derive(Debug)]
struct UdpSocket {
    io: tokio::net::UdpSocket,
    inner: Arc<udp::UdpSocketState>,
    send: Option<Arc<SendThread>>,
    seal: bool,
    recv: Option<Arc<RecvThread>>,
}

impl AsyncUdpSocket for UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn super::UdpPoller>> {
        if let Some(send) = &self.send {
            return Box::pin(SendQueuePoller(send.clone()));
        }
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn send_thread(&self) -> bool {
        self.send.is_some()
    }

    fn seal_thread(&self) -> bool {
        self.seal
    }

    fn decrypt_thread(&self) -> bool {
        self.recv.as_ref().is_some_and(|r| r.decrypt)
    }

    fn set_recv_keys(&self, keys: proto::RecvKeys) {
        if let Some(r) = &self.recv {
            *r.keys.lock().unwrap() = Some(Arc::new(keys));
        }
    }

    fn try_send_owned(
        &self,
        meta: &udp::Transmit,
        len: usize,
        buf: &mut Vec<u8>,
        seals: &mut Vec<proto::SealJob>,
    ) -> io::Result<()> {
        let Some(s) = &self.send else {
            return Err(io::ErrorKind::Unsupported.into());
        };
        if s.queued.load(Ordering::Acquire) >= send_queue() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let (fresh, fresh_seals) = s.free.lock().unwrap().pop().unwrap_or_default();
        let job = SendJob {
            destination: meta.destination,
            ecn: meta.ecn,
            segment_size: meta.segment_size,
            src_ip: meta.src_ip,
            len,
            buf: mem::replace(buf, fresh),
            seals: mem::replace(seals, fresh_seals),
        };
        s.queued.fetch_add(1, Ordering::AcqRel);
        s.tx.send(job)
            .map_err(|_| io::Error::other("quinn send thread is gone"))
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Some(r) = &self.recv {
            return r.poll_take(cx, bufs, meta);
        }
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

/// Transmits the send thread may hold at once; past this the connection
/// waits. QUINN_SEND_QUEUE sets it (16 when unset): each one held is up to
/// MAX_TRANSMIT_SEGMENTS packets of waiting inside the sender.
fn send_queue() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("QUINN_SEND_QUEUE")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or(16)
    })
}

struct SendJob {
    destination: SocketAddr,
    ecn: Option<udp::EcnCodepoint>,
    segment_size: Option<usize>,
    src_ip: Option<IpAddr>,
    len: usize,
    buf: Vec<u8>,
    seals: Vec<proto::SealJob>,
}

/// How often an idle send or receive thread checks whether its socket is gone
const THREAD_CHECK: Duration = Duration::from_secs(1);

/// B and C: a thread that seals what was left unsealed and calls sendmsg,
/// in the order transmits were handed over
#[derive(Debug)]
struct SendThread {
    tx: mpsc::SyncSender<SendJob>,
    queued: AtomicUsize,
    /// The one task waiting for room (one connection a socket, in this experiment)
    waker: Mutex<Option<Waker>>,
    free: Mutex<Vec<(Vec<u8>, Vec<proto::SealJob>)>>,
}

impl SendThread {
    fn start(sock: std::net::UdpSocket, state: Arc<udp::UdpSocketState>) -> io::Result<Arc<Self>> {
        let (tx, rx) = mpsc::sync_channel::<SendJob>(send_queue());
        let shared = Arc::new(Self {
            tx,
            queued: AtomicUsize::new(0),
            waker: Mutex::new(None),
            free: Mutex::new(Vec::new()),
        });
        let me = shared.clone();
        std::thread::Builder::new()
            .name("quinn-send".into())
            .spawn(move || {
                // `me` holds the channel's sender, so the channel never closes:
                // the thread ends when it holds the last reference, which is
                // when the socket was dropped, and its copy of the socket with it
                loop {
                    let mut job = match rx.recv_timeout(THREAD_CHECK) {
                        Ok(job) => job,
                        Err(mpsc::RecvTimeoutError::Timeout) if Arc::strong_count(&me) > 1 => {
                            continue;
                        }
                        Err(_) => return,
                    };
                    for s in &job.seals {
                        s.seal(&mut job.buf);
                    }
                    let t = udp::Transmit {
                        destination: job.destination,
                        ecn: job.ecn,
                        contents: &job.buf[..job.len],
                        segment_size: job.segment_size,
                        src_ip: job.src_ip,
                    };
                    loop {
                        match state.send((&sock).into(), &t) {
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                if Arc::strong_count(&me) == 1 {
                                    return;
                                }
                                state.wait((&sock).into(), true)
                            }
                            _ => break,
                        }
                    }
                    job.buf.clear();
                    job.seals.clear();
                    me.free.lock().unwrap().push((job.buf, job.seals));
                    me.queued.fetch_sub(1, Ordering::AcqRel);
                    if let Some(w) = me.waker.lock().unwrap().take() {
                        w.wake();
                    }
                }
            })?;
        Ok(shared)
    }
}

/// Writable while the send thread has room
#[derive(Debug)]
struct SendQueuePoller(Arc<SendThread>);

impl super::UdpPoller for SendQueuePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let s = &self.0;
        if s.queued.load(Ordering::Acquire) < send_queue() {
            return Poll::Ready(Ok(()));
        }
        *s.waker.lock().unwrap() = Some(cx.waker().clone());
        match s.queued.load(Ordering::Acquire) < send_queue() {
            true => Poll::Ready(Ok(())),
            false => Poll::Pending,
        }
    }
}

/// Bytes a received datagram (or GRO train) may take
const RECV_CHUNK: usize = 64 * 1024;
/// Batches the receive thread may hold before it waits for the endpoint
const RECV_QUEUE: usize = 8;

#[derive(Debug)]
struct RecvBatch {
    buf: Vec<u8>,
    metas: [udp::RecvMeta; udp::BATCH_SIZE],
    n: usize,
    next: usize,
}

/// D: a thread that calls recvmmsg and queues what it got for the endpoint
#[derive(Debug)]
struct RecvThread {
    decrypt: bool,
    keys: Mutex<Option<Arc<proto::RecvKeys>>>,
    queue: Mutex<VecDeque<RecvBatch>>,
    room: Condvar,
    waker: Mutex<Option<Waker>>,
    free: Mutex<Vec<RecvBatch>>,
}

impl RecvThread {
    fn start(
        sock: std::net::UdpSocket,
        state: Arc<udp::UdpSocketState>,
        decrypt: bool,
    ) -> io::Result<Arc<Self>> {
        let shared = Arc::new(Self {
            decrypt,
            keys: Mutex::new(None),
            queue: Mutex::new(VecDeque::new()),
            room: Condvar::new(),
            waker: Mutex::new(None),
            free: Mutex::new(Vec::new()),
        });
        let me = shared.clone();
        std::thread::Builder::new()
            .name("quinn-recv".into())
            .spawn(move || {
                let mut opener = Opener::default();
                loop {
                    let mut b = me.free.lock().unwrap().pop().unwrap_or_else(|| RecvBatch {
                        buf: vec![0; RECV_CHUNK * udp::BATCH_SIZE],
                        metas: [udp::RecvMeta::default(); udp::BATCH_SIZE],
                        n: 0,
                        next: 0,
                    });
                    b.n = loop {
                        let mut iovs: Vec<IoSliceMut<'_>> =
                            b.buf.chunks_mut(RECV_CHUNK).map(IoSliceMut::new).collect();
                        match state.recv((&sock).into(), &mut iovs, &mut b.metas) {
                            Ok(n) => break n,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                // Only this thread holds it: the socket was dropped
                                if Arc::strong_count(&me) == 1 {
                                    return;
                                }
                                // Wakes at least once a second (quinn-udp's wait)
                                state.wait((&sock).into(), false)
                            }
                            Err(_) => {}
                        }
                    };
                    b.next = 0;
                    if me.decrypt {
                        let keys = me.keys.lock().unwrap().clone();
                        if let Some(keys) = keys {
                            for i in 0..b.n {
                                let m = &mut b.metas[i];
                                let off = i * RECV_CHUNK;
                                m.predecrypted =
                                    opener.open(&keys, &mut b.buf[off..off + m.len], m.stride);
                            }
                        }
                    }
                    {
                        let mut q = me.queue.lock().unwrap();
                        while q.len() >= RECV_QUEUE {
                            q = me.room.wait_timeout(q, THREAD_CHECK).unwrap().0;
                            if Arc::strong_count(&me) == 1 {
                                return;
                            }
                        }
                        q.push_back(b);
                    }
                    if let Some(w) = me.waker.lock().unwrap().take() {
                        w.wake();
                    }
                }
            })?;
        Ok(shared)
    }

    /// What `poll_recv` returns: datagrams copied out of the queued batches
    fn poll_take(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut q = self.queue.lock().unwrap();
        if q.is_empty() {
            // Set under the queue's lock: the thread pushes under it, then wakes
            *self.waker.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut done = 0;
        while done < bufs.len().min(meta.len()) {
            let Some(b) = q.front_mut() else { break };
            while b.next < b.n && done < bufs.len().min(meta.len()) {
                let m = b.metas[b.next];
                let off = b.next * RECV_CHUNK;
                bufs[done][..m.len].copy_from_slice(&b.buf[off..off + m.len]);
                meta[done] = m;
                b.next += 1;
                done += 1;
            }
            if b.next == b.n {
                let b = q.pop_front().expect("front exists");
                self.free.lock().unwrap().push(b);
                self.room.notify_one();
            }
        }
        Poll::Ready(Ok(done))
    }
}

/// E: opens 1-RTT packets on the receive thread
#[derive(Default)]
struct Opener {
    /// The keys `largest` was last seeded from
    seeded: Option<usize>,
    largest: u64,
    failed: u64,
    opened: u64,
}

impl Opener {
    /// Opens every segment of one datagram in place, or none: true when it did
    fn open(&mut self, keys: &proto::RecvKeys, dgram: &mut [u8], stride: usize) -> bool {
        let key = Arc::as_ptr(&keys.packet) as *const () as usize;
        if self.seeded != Some(key) {
            self.seeded = Some(key);
            self.largest = self.largest.max(keys.largest);
        }
        let stride = if stride == 0 { dgram.len() } else { stride };
        let pn_offset = 1 + keys.cid_len;
        let min = pn_offset + 4 + keys.header.sample_size();
        // Pass 1: every segment a short header of the current phase, or none touched
        let mut unprotected = 0;
        let mut ok = true;
        for seg in dgram.chunks_mut(stride) {
            if seg.len() < min || seg[0] & 0x80 != 0 {
                ok = false;
                break;
            }
            keys.header.decrypt(pn_offset, seg);
            unprotected += 1;
            if (seg[0] & 0x04 != 0) != keys.key_phase {
                ok = false;
                break;
            }
        }
        if !ok {
            for seg in dgram.chunks_mut(stride).take(unprotected) {
                keys.header.encrypt(pn_offset, seg);
            }
            return false;
        }
        // Pass 2: decrypt each
        for seg in dgram.chunks_mut(stride) {
            let pn_len = (seg[0] & 0x03) as usize + 1;
            let mut truncated = 0u64;
            for &b in &seg[pn_offset..pn_offset + pn_len] {
                truncated = (truncated << 8) | u64::from(b);
            }
            let number = expand_pn(truncated, pn_len, self.largest + 1);
            let header_len = pn_offset + pn_len;
            let (header, payload) = seg.split_at_mut(header_len);
            match keys.packet.decrypt_in_place(number, header, payload) {
                Ok(_) => {
                    self.largest = self.largest.max(number);
                    self.opened += 1;
                }
                Err(_) => {
                    // Routed nowhere, so lost; QUIC sends it again
                    header[1..pn_offset].fill(0);
                    self.failed += 1;
                    if self.failed.is_power_of_two() {
                        eprintln!(
                            "quinn-recv: {} packets failed to open, {} opened",
                            self.failed, self.opened
                        );
                    }
                }
            }
        }
        true
    }
}

/// RFC 9000, appendix A.3
fn expand_pn(truncated: u64, pn_len: usize, expected: u64) -> u64 {
    let win = 1u64 << (pn_len * 8);
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if expected >= hwin && candidate <= expected - hwin && candidate < (1u64 << 62) - win {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}
