use super::*;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use std::io::{IoSlice, Seek, SeekFrom};

fn send_descriptors(client: &UnixStream, fds: &[BorrowedFd<'_>]) {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
    assert_eq!(
        net::sendmsg(
            client,
            &[IoSlice::new(&[0])],
            &mut control,
            SendFlags::empty()
        )
        .unwrap(),
        1,
    );
}

fn read_frame(conn: &Connection) -> Frame {
    frame(conn, Duration::from_secs(2)).unwrap().unwrap()
}

#[test]
fn pipelined_fd_scan_preserves_offset_and_next_command() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"harmless fixture").unwrap();
    file.seek(SeekFrom::Start(3)).unwrap();
    client.write_all(b"zIDSESSION\0zFILDES\0").unwrap();
    send_descriptors(&client, &[file.as_fd()]);
    client.write_all(b"nPING\r\nzEND\0").unwrap();

    let conn = Connection::Unix(server);
    assert_eq!(read_frame(&conn).command, b"IDSESSION");
    assert_eq!(read_frame(&conn).command, b"FILDES");
    let Connection::Unix(server) = &conn else {
        unreachable!()
    };
    let mut data = Vec::new();
    FromStart(receive_fd(server).unwrap(), 0)
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"harmless fixture");
    assert_eq!(file.stream_position().unwrap(), 3);
    let ping = read_frame(&conn);
    assert_eq!((ping.command.as_slice(), ping.term), (&b"PING"[..], b'\n'));
    assert_eq!(read_frame(&conn).command, b"END");
}

#[test]
fn received_descriptors_close_on_drop_or_rejection() {
    for count in 1..=4 {
        let (client, server) = UnixStream::pair().unwrap();
        let (mut observer, sent) = UnixStream::pair().unwrap();
        observer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        send_descriptors(&client, &vec![sent.as_fd(); count]);
        drop(sent);
        let received = receive_fd(&server);
        assert_eq!(received.is_ok(), count == 1);
        drop(received);
        let mut byte = [0];
        assert_eq!(
            observer.read(&mut byte).ok(),
            Some(0),
            "leaked descriptor at count {count}"
        );
    }
}

#[test]
fn missing_descriptor_and_disconnected_sender() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&[0]).unwrap();
    assert!(receive_fd(&server).is_err());
    drop(client);
    assert!(receive_fd(&server).is_err());
}

fn chunks(conn: &Connection, quota: u64) -> Chunks<'_> {
    conn.read_timeout(Duration::from_secs(1)).unwrap();
    Chunks {
        conn,
        left: 0,
        quota,
        complete: false,
        overflow: false,
    }
}

#[test]
fn chunk_lengths_preserve_next_frame_and_enforce_total_quota() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .write_all(b"\0\0\0\x02ab\0\0\0\x01c\0\0\0\0nPING\n\0\0\0\x02ab\0\0\0\x02")
        .unwrap();
    let conn = Connection::Unix(server);
    let mut body = chunks(&conn, 3);
    let mut data = Vec::new();
    body.read_to_end(&mut data).unwrap();
    assert!(body.complete);
    assert_eq!(data, b"abc");
    assert_eq!(read_frame(&conn).command, b"PING");
    let mut body = chunks(&conn, 3);
    assert!(body.read_to_end(&mut data).is_err());
    assert!(body.overflow);
}

#[test]
fn legacy_ping_needs_no_terminator() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(b"PING").unwrap();
    let frame = read_frame(&Connection::Unix(server));
    assert!(frame.legacy);
    assert_eq!(frame.command, b"PING");
    assert_eq!(frame.term, b'\n');
}

#[test]
fn oversized_complete_upload_gets_error_and_eof() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let mut upload = 1025_u32.to_be_bytes().to_vec();
    upload.extend([0x61; 1025]);
    upload.extend(0_u32.to_be_bytes());
    client.write_all(&upload).unwrap();
    let conn = Connection::Unix(server);
    let mut body = chunks(&conn, 1024);
    assert!(body.read(&mut [0]).is_err());
    assert!(body.overflow);
    (&conn)
        .write_all(b"INSTREAM size limit exceeded. ERROR\0")
        .unwrap();
    conn.finish_input().unwrap();
    drop(conn);
    let mut result = Vec::new();
    client.read_to_end(&mut result).unwrap();
    assert_eq!(result, b"INSTREAM size limit exceeded. ERROR\0");
}
