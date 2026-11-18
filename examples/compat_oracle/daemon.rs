use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub fn exchange(mut stream: impl Read + Write, bytes: &[u8]) -> io::Result<String> {
    stream.write_all(bytes)?;
    let mut reply = Vec::new();
    stream.take(65537).read_to_end(&mut reply)?;
    if reply.len() > 65536 {
        return Err(io::Error::other("daemon reply exceeds 64 KiB"));
    }
    String::from_utf8(reply).map_err(io::Error::other)
}

pub fn unix_request(socket: &Path, bytes: &[u8]) -> io::Result<String> {
    let connection = UnixStream::connect(socket)?;
    connection.set_read_timeout(Some(Duration::from_secs(10)))?;
    connection.set_write_timeout(Some(Duration::from_secs(10)))?;
    exchange(connection, bytes)
}

pub fn stream_frame(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut frame = b"zINSTREAM\0".to_vec();
    if !data.is_empty() {
        let size = u32::try_from(data.len()).map_err(io::Error::other)?;
        frame.extend_from_slice(&size.to_be_bytes());
        frame.extend_from_slice(data);
    }
    frame.extend_from_slice(&[0; 4]);
    Ok(frame)
}

pub struct Daemon(Child);

impl Daemon {
    pub fn start(executable: &Path, config: &Path, socket: &Path) -> io::Result<Self> {
        let log = config.with_extension("log");
        let output = File::create(&log)?;
        let mut daemon = Self(
            Command::new(executable)
                .arg("--config-file")
                .arg(config)
                .env("LC_ALL", "C")
                .env("TZ", "UTC")
                .stdin(Stdio::null())
                .stdout(output.try_clone()?)
                .stderr(output)
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if let Some(status) = daemon.0.try_wait()? {
                let message = fs::read_to_string(&log)?;
                return Err(io::Error::other(format!(
                    "daemon exited {status}: {message}"
                )));
            }
            match unix_request(socket, b"zPING\0") {
                Ok(reply) if reply == "PONG\0" => return Ok(daemon),
                Ok(reply) => {
                    return Err(io::Error::other(format!("unexpected PING reply {reply:?}")));
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "daemon did not become ready",
        ))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
