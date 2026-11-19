use std::io;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, Scope};
use std::time::Duration;

use super::{Connection, State};

type Task<'a> = Box<dyn FnOnce() -> io::Result<()> + Send + 'a>;

// An idle worker can take the next file without creating another thread. The
// rendezvous channel never queues files, descriptors, or requests in memory.
pub(super) struct Jobs<'a, 'env> {
    scope: &'a Scope<'a, 'env>,
    state: &'a State,
    conn: &'a Connection,
    sender: SyncSender<Task<'a>>,
    receiver: Arc<Mutex<Receiver<Task<'a>>>>,
}

impl<'a, 'env> Jobs<'a, 'env> {
    pub(super) fn new(scope: &'a Scope<'a, 'env>, state: &'a State, conn: &'a Connection) -> Self {
        let (sender, receiver) = sync_channel(0);
        Self {
            scope,
            state,
            conn,
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    pub(super) fn idle(&self) -> bool {
        Arc::strong_count(&self.receiver) == 1
    }

    pub(super) fn submit(
        &self,
        run: impl FnOnce() -> io::Result<()> + Send + 'a,
    ) -> io::Result<()> {
        if let Some(task) = self.try_submit(run)? {
            task()?;
        }
        Ok(())
    }

    pub(super) fn try_submit(
        &self,
        run: impl FnOnce() -> io::Result<()> + Send + 'a,
    ) -> io::Result<Option<Task<'a>>> {
        let task = match self.sender.try_send(Box::new(run)) {
            Ok(()) => return Ok(None),
            Err(TrySendError::Full(task) | TrySendError::Disconnected(task)) => task,
        };
        let Some(slot) = self.state.try_scan_slot() else {
            return Ok(Some(task));
        };
        let receiver = self.receiver.clone();
        let conn = self.conn;
        thread::Builder::new().spawn_scoped(self.scope, move || {
            let _slot = slot;
            let mut next = task;
            loop {
                if next().is_err() {
                    let _ = rustix::net::shutdown(conn, rustix::net::Shutdown::Both);
                    break;
                }
                let received = receiver
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_millis(1));
                match received {
                    Ok(task) => next = task,
                    Err(_) => break,
                }
            }
        })?;
        Ok(None)
    }
}
