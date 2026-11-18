mod config;
mod engine;
mod listeners;
mod protocol;
mod service;

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, poll};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGUSR2};
use socket2::{SockRef, Socket};

use config::Config;
use engine::Generation;
use protocol::Connection;
use service::{Log, PidFile};

struct Client {
    connection: Connection,
    session: Option<u64>,
    expires: Option<Instant>,
}

impl Client {
    fn waiting(connection: Connection, session: Option<u64>, timeout: Duration) -> Self {
        let expires = (!timeout.is_zero())
            .then(|| Instant::now().checked_add(timeout))
            .flatten();
        Self {
            connection,
            session,
            expires,
        }
    }
    fn expired(&self) -> bool {
        self.expires.is_some_and(|end| Instant::now() >= end)
    }
    fn timeout(&self) {
        let _ = rustix::net::send(
            &self.connection,
            b"COMMAND READ TIMED OUT\n",
            rustix::net::SendFlags::DONTWAIT,
        );
    }
}

#[derive(Default)]
struct Clients {
    pending: VecDeque<Client>,
    // The supervisor polls idle sockets. Workers return sessions here between commands.
    returned: Vec<Client>,
    waiting: usize,
    // A duplicate lets the supervisor interrupt blocking operations at shutdown.
    active: HashMap<thread::ThreadId, Socket>,
    activity: HashMap<thread::ThreadId, (String, Instant)>,
    scan_slots: HashMap<u64, Instant>,
    next_slot: u64,
    workers: usize,
}

impl Clients {
    fn jobs(&self) -> usize {
        self.waiting + self.pending.len() + self.active.len() + self.scan_slots.len()
    }
}

struct ScanSlot<'a> {
    state: &'a State,
    id: u64,
}

impl Drop for ScanSlot<'_> {
    fn drop(&mut self) {
        self.state
            .clients
            .lock()
            .unwrap()
            .scan_slots
            .remove(&self.id);
        self.state.wake_supervisor();
    }
}

struct State {
    config: Config,
    generation: RwLock<Arc<Generation>>,
    clients: Mutex<Clients>,
    work: Condvar,
    shutdown: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
    log: Mutex<Log>,
    wake: UnixStream,
}

impl State {
    fn snapshot(&self) -> Arc<Generation> {
        self.generation.read().unwrap().clone()
    }
    fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.work.notify_all();
        self.wake_supervisor();
    }
    fn stopping(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
    fn request_reload(&self) {
        self.reload.store(true, Ordering::Release);
        self.wake_supervisor();
    }
    fn wake_supervisor(&self) {
        // A full nonblocking socket already contains a pending notification.
        let _ = (&self.wake).write(&[1]);
    }
    fn log(&self, message: &str) {
        if let Err(e) = self.log.lock().unwrap().write(&self.config, message) {
            eprintln!("clamd log: {e}");
        }
    }
    fn try_scan_slot(&self) -> Option<ScanSlot<'_>> {
        let mut clients = self.clients.lock().unwrap();
        if self.stopping()
            || !clients.pending.is_empty()
            || clients.workers + clients.scan_slots.len() >= self.config.max_threads
            || clients.jobs() >= self.config.max_queue
        {
            return None;
        }
        let id = clients.next_slot;
        clients.next_slot = id.wrapping_add(1);
        clients.scan_slots.insert(id, Instant::now());
        Some(ScanSlot { state: self, id })
    }

    fn set_activity(&self, command: &str) {
        if let Some((name, since)) = self
            .clients
            .lock()
            .unwrap()
            .activity
            .get_mut(&thread::current().id())
        {
            name.clear();
            name.push_str(command);
            *since = Instant::now();
        }
    }

    fn stats(&self) -> String {
        use std::fmt::Write;
        let clients = self.clients.lock().unwrap();
        let mut out = format!(
            "POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live {}  idle {} max {} idle-timeout {}\nQUEUE: {} items\n",
            clients.workers + clients.scan_slots.len(),
            clients.workers.saturating_sub(clients.active.len()),
            self.config.max_threads,
            self.config.idle_timeout.as_secs(),
            clients.pending.len()
        );
        for (command, since) in clients.activity.values() {
            writeln!(out, "\t{command} {:.6} ", since.elapsed().as_secs_f64()).unwrap();
        }
        for since in clients.scan_slots.values() {
            writeln!(out, "\tSCAN {:.6} ", since.elapsed().as_secs_f64()).unwrap();
        }
        out.push_str("\nMEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A pools 1 pools_used N/A pools_total N/A");
        out
    }

    fn schedule(
        self: &Arc<Self>,
        clients: &mut Clients,
        workers: &mut Vec<JoinHandle<()>>,
    ) -> io::Result<()> {
        while clients.workers + clients.scan_slots.len() < self.config.max_threads
            && clients.pending.len() > clients.workers - clients.active.len()
        {
            let worker = self.clone();
            workers.push(
                thread::Builder::new()
                    .name("clamd-client".into())
                    .spawn(move || worker.worker())?,
            );
            clients.workers += 1;
        }
        Ok(())
    }

    fn reload_database(&self) {
        let outcome = if self.config.concurrent_reload {
            Generation::load(&self.config)
                .map(|next| *self.generation.write().unwrap() = Arc::new(next))
        } else {
            // Block new scan snapshots and let in-flight scans release their old version.
            // Keep the validated old version available in case loading the replacement fails.
            let mut current = self.generation.write().unwrap();
            while Arc::strong_count(&*current) > 1 && !self.stopping() {
                thread::sleep(Duration::from_millis(20));
            }
            if self.stopping() {
                return;
            }
            Generation::load(&self.config).map(|next| *current = Arc::new(next))
        };
        match outcome {
            Ok(()) => self.log("Database reloaded"),
            Err(e) => self.log(&format!(
                "Database reload failed; keeping current generation: {e}"
            )),
        }
    }

    fn worker(&self) {
        let id = thread::current().id();
        let mut clients = self.clients.lock().unwrap();
        loop {
            clients.activity.insert(id, ("IDLE".into(), Instant::now()));
            while !self.stopping() && clients.pending.is_empty() {
                if self.config.idle_timeout.is_zero() {
                    clients = self.work.wait(clients).unwrap();
                } else {
                    let (next, wait) = self
                        .work
                        .wait_timeout(clients, self.config.idle_timeout)
                        .unwrap();
                    clients = next;
                    if wait.timed_out() && clients.pending.is_empty() {
                        clients.activity.remove(&id);
                        clients.workers -= 1;
                        return;
                    }
                }
            }
            if self.stopping() {
                clients.activity.remove(&id);
                clients.workers -= 1;
                return;
            }
            let Some(client) = clients.pending.pop_front() else {
                continue;
            };
            let connection = client.connection;
            let socket = SockRef::from(&connection);
            let write_timeout =
                (!self.config.send_buf_timeout.is_zero()).then_some(self.config.send_buf_timeout);
            match socket
                .set_write_timeout(write_timeout)
                .and_then(|_| socket.try_clone())
            {
                Ok(socket) => {
                    clients.active.insert(id, socket);
                }
                Err(error) => {
                    self.log(&format!("Client socket setup failed: {error}"));
                    continue;
                }
            }
            drop(clients);
            self.set_activity("COMMAND");
            let result = protocol::handle(&connection, self, client.session);
            clients = self.clients.lock().unwrap();
            let was_full = clients.jobs() == self.config.max_queue;
            clients.active.remove(&id);
            match result {
                Ok(Some(next)) if !self.stopping() => {
                    clients.waiting += 1;
                    clients.returned.push(Client::waiting(
                        connection,
                        Some(next),
                        self.config.read_timeout,
                    ));
                    self.wake_supervisor();
                }
                Err(error) if self.config.log_verbose || self.config.debug => {
                    self.log(&format!("Client disconnected: {error}"))
                }
                _ => {}
            }
            if was_full {
                self.wake_supervisor();
            }
        }
    }

    fn disconnect(&self) {
        self.stop();
        let mut clients = self.clients.lock().unwrap();
        clients.pending.clear();
        clients.returned.clear();
        for socket in clients.active.values() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        self.work.notify_all();
    }
}

struct Signals(Vec<signal_hook::SigId>);
impl Drop for Signals {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

fn serve(
    state: &Arc<State>,
    listeners: &[listeners::Listener],
    wake: UnixStream,
) -> io::Result<()> {
    let reopen = Arc::new(AtomicBool::new(false));
    let mut signals = Signals(Vec::new());
    for (sig, flag) in [
        (SIGTERM, &state.shutdown),
        (SIGINT, &state.shutdown),
        (SIGHUP, &reopen),
        (SIGUSR2, &state.reload),
    ] {
        signals
            .0
            .push(signal_hook::flag::register(sig, flag.clone())?);
        signals.0.push(signal_hook::low_level::pipe::register(
            sig,
            state.wake.try_clone()?,
        )?);
    }
    state.log("clamd ready; incomplete detection coverage is reported as a scan error");
    if !state.config.partial_engine_options.is_empty() {
        state.log(&format!(
            "Configuration for incomplete detection stages: {}",
            state.config.partial_engine_options.join(", ")
        ));
    }
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let mut waiting: Vec<Client> = Vec::new();
    let mut loader: Option<JoinHandle<()>> = None;
    let mut last_check = Instant::now();
    let result = (|| -> io::Result<()> {
        while !state.stopping() {
            if reopen.swap(false, Ordering::AcqRel) {
                let result = state.log.lock().unwrap().reopen(&state.config);
                match result {
                    Ok(()) => state.log("Log reopened"),
                    Err(e) => state.log(&format!("Log reopen failed: {e}")),
                }
            }
            if loader.as_ref().is_some_and(|task| task.is_finished()) {
                loader
                    .take()
                    .unwrap()
                    .join()
                    .map_err(|_| io::Error::other("reload worker failed"))?;
            }
            if loader.is_none() {
                let mut reload = state.reload.swap(false, Ordering::AcqRel);
                if !state.config.self_check.is_zero()
                    && last_check.elapsed() >= state.config.self_check
                {
                    last_check = Instant::now();
                    match state.snapshot().changed(&state.config) {
                        Ok(changed) => reload |= changed,
                        Err(e) => state.log(&format!("Database self-check failed: {e}")),
                    }
                }
                if reload {
                    let shared = state.clone();
                    loader = Some(
                        thread::Builder::new()
                            .name("clamd-reload".into())
                            .spawn(move || shared.reload_database())?,
                    );
                }
            }
            workers.retain(|thread| !thread.is_finished());
            let has_capacity = {
                let mut c = state.clients.lock().unwrap();
                waiting.append(&mut c.returned);
                state.schedule(&mut c, &mut workers)?;
                c.jobs() < state.config.max_queue
            };
            let mut fds: Vec<_> = if has_capacity {
                listeners
                    .iter()
                    .map(|l| PollFd::new(l.as_fd(), PollFlags::POLLIN))
                    .collect()
            } else {
                Vec::new()
            };
            let listener_count = fds.len();
            fds.push(PollFd::new(wake.as_fd(), PollFlags::POLLIN));
            fds.extend(
                waiting
                    .iter()
                    .map(|c| PollFd::new(c.connection.as_fd(), PollFlags::POLLIN)),
            );
            let timeout = waiting
                .iter()
                .filter_map(|c| c.expires)
                .min()
                .map_or(1000, |t| {
                    t.saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(1000) as u16
                });
            match poll(&mut fds[..], timeout) {
                Ok(_) => (),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
            if fds[listener_count]
                .revents()
                .is_some_and(|f| f.contains(PollFlags::POLLIN))
            {
                let mut buf = [0; 512];
                let _ = (&wake).read(&mut buf);
            }
            let events: Vec<_> = fds
                .iter()
                .map(|fd| fd.revents().unwrap_or_else(PollFlags::empty))
                .collect();
            drop(fds);
            {
                let mut clients = state.clients.lock().unwrap();
                for (i, event) in events[listener_count + 1..].iter().enumerate().rev() {
                    if event.is_empty() && !waiting[i].expired() {
                        continue;
                    }
                    let client = waiting.swap_remove(i);
                    clients.waiting -= 1;
                    if event.contains(PollFlags::POLLIN) {
                        clients.pending.push_back(client);
                        state.work.notify_one();
                    } else if client.expired() {
                        client.timeout();
                    }
                }
                state.schedule(&mut clients, &mut workers)?;
            }
            for (listener, &flags) in listeners.iter().zip(&events[..listener_count]) {
                if flags.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
                    return Err(io::Error::other("listening socket closed"));
                }
                if !flags.contains(PollFlags::POLLIN) {
                    continue;
                }
                for _ in 0..state.config.max_queue {
                    let mut clients = state.clients.lock().unwrap();
                    if state.stopping() || clients.jobs() >= state.config.max_queue {
                        break;
                    }
                    let connection = match listener.accept() {
                        Ok(connection) => connection,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    };
                    waiting.push(Client::waiting(
                        connection,
                        None,
                        state.config.command_read_timeout,
                    ));
                    clients.waiting += 1;
                }
            }
        }
        Ok(())
    })();
    state.disconnect();
    for worker in workers {
        let _ = worker.join();
    }
    if let Some(loader) = loader {
        let _ = loader.join();
    }
    state.log("clamd stopped");
    result
}

pub(crate) fn run(args: &[OsString]) -> io::Result<()> {
    let Some(config) = config::arguments(args)? else {
        return Ok(());
    };
    service::drop_privileges(config.user.as_deref())?;
    let log = Log::open(&config)?;
    let generation = Generation::load(&config)?;
    let mut pid_file = config.pid_file.as_deref().map(PidFile::open).transpose()?;
    let listeners = listeners::open(&config)?;
    if !config.foreground {
        service::detach()?;
    }
    if let Some(pid) = &mut pid_file {
        pid.publish()?;
    }
    let (wake, receiver) = UnixStream::pair()?;
    wake.set_nonblocking(true)?;
    receiver.set_nonblocking(true)?;
    let state = Arc::new(State {
        config,
        generation: RwLock::new(Arc::new(generation)),
        clients: Mutex::new(Clients::default()),
        work: Condvar::new(),
        shutdown: Arc::new(AtomicBool::new(false)),
        reload: Arc::new(AtomicBool::new(false)),
        log: Mutex::new(log),
        wake,
    });
    serve(&state, &listeners, receiver)
}
