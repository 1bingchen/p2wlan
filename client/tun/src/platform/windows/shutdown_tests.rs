use super::*;
use std::ffi::c_void;
use std::sync::atomic::AtomicUsize;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct ReaderState {
    received: AtomicUsize,
    reader_exited: AtomicBool,
    session_ended: AtomicBool,
    ended_before_reader: AtomicBool,
    released_after_end: AtomicBool,
    adapter_closed: AtomicBool,
    hold_receive: Mutex<bool>,
    receive_gate: Condvar,
}

unsafe fn state<'a>(pointer: *mut c_void) -> &'a ReaderState {
    &*pointer.cast::<ReaderState>()
}

unsafe extern "C" fn receive(session: *mut c_void, size: *mut u32) -> *mut u8 {
    static PACKET: [u8; 4] = [0x45, 0, 0, 4];
    let state = state(session);
    state.received.fetch_add(1, Ordering::SeqCst);
    let mut held = state.hold_receive.lock().unwrap();
    while *held {
        held = state.receive_gate.wait(held).unwrap();
    }
    *size = PACKET.len() as u32;
    PACKET.as_ptr().cast_mut()
}

unsafe extern "C" fn release(session: *mut c_void, _packet: *const u8) {
    let state = state(session);
    if state.session_ended.load(Ordering::SeqCst) {
        state.released_after_end.store(true, Ordering::SeqCst);
    }
}

unsafe extern "C" fn read_event(_session: *mut c_void) -> *mut c_void {
    // These fixtures always return a packet, so the reader never waits on
    // this non-null sentinel or invokes any real Wintun/driver operation.
    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
}

unsafe extern "C" fn end_session(session: *mut c_void) {
    let state = state(session);
    state.ended_before_reader.store(
        !state.reader_exited.load(Ordering::SeqCst),
        Ordering::SeqCst,
    );
    state.session_ended.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn close_adapter(adapter: *mut c_void) {
    state(adapter).adapter_closed.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn create_adapter(
    _name: *const u16,
    _kind: *const u16,
    _guid: *const Guid,
) -> *mut c_void {
    std::ptr::null_mut()
}
unsafe extern "C" fn open_adapter(_name: *const u16) -> *mut c_void {
    std::ptr::null_mut()
}
unsafe extern "C" fn start_session(_adapter: *mut c_void, _capacity: u32) -> *mut c_void {
    std::ptr::null_mut()
}
unsafe extern "C" fn allocate_packet(_session: *mut c_void, _size: u32) -> *mut u8 {
    std::ptr::null_mut()
}
unsafe extern "C" fn send_packet(_session: *mut c_void, _packet: *const u8) {}
unsafe extern "C" fn adapter_luid(_adapter: *mut c_void, luid: *mut u64) {
    *luid = 0;
}

fn fixture(state: &Arc<ReaderState>) -> WintunDevice {
    let api = Arc::new(WintunApi {
        // Retain a real library handle without requiring Wintun installation.
        _lib: unsafe { Library::new("kernel32.dll").unwrap() },
        create_adapter,
        open_adapter,
        close_adapter,
        start_session,
        end_session,
        get_read_wait_event: read_event,
        receive_packet: receive,
        release_receive_packet: release,
        allocate_send_packet: allocate_packet,
        send_packet,
        get_adapter_luid: adapter_luid,
    });
    let (tx, rx) = mpsc::channel(1);
    let shutdown = Arc::new(AtomicBool::new(false));
    let pointer = Arc::as_ptr(state) as usize;
    let reader = spawn_read_thread(pointer, receive, release, read_event, tx, shutdown.clone());
    let reader_state = state.clone();
    let watched_reader = thread::spawn(move || {
        reader.join().unwrap();
        reader_state.reader_exited.store(true, Ordering::SeqCst);
    });
    WintunDevice {
        session: pointer,
        adapter: pointer,
        api,
        read_rx: rx,
        shutdown,
        read_thread: Some(watched_reader),
        name: "shutdown-fixture".into(),
        mtu: 1420,
        address: "10.0.0.1".into(),
        is_up: true,
    }
}

fn wait_until(condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "reader fixture did not reach barrier"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn assert_clean_shutdown(state: &ReaderState) {
    assert!(state.reader_exited.load(Ordering::SeqCst));
    assert!(state.session_ended.load(Ordering::SeqCst));
    assert!(state.adapter_closed.load(Ordering::SeqCst));
    assert!(!state.ended_before_reader.load(Ordering::SeqCst));
    assert!(!state.released_after_end.load(Ordering::SeqCst));
}

#[test]
fn full_receive_queue_does_not_deadlock_device_drop() {
    let state = Arc::new(ReaderState::default());
    let device = fixture(&state);
    // The second packet cannot enter the one-slot queue until the receiver
    // drains or closes it. No consumer runs during this test.
    wait_until(|| state.received.load(Ordering::SeqCst) >= 2);
    let (done, stopped) = std::sync::mpsc::channel();
    let closer = thread::spawn(move || {
        drop(device);
        done.send(()).unwrap();
    });
    stopped
        .recv_timeout(Duration::from_secs(2))
        .expect("device Drop blocked behind a full receive queue");
    closer.join().unwrap();
    assert_clean_shutdown(&state);
}

#[test]
fn in_flight_packet_finishes_before_session_is_released() {
    let state = Arc::new(ReaderState::default());
    *state.hold_receive.lock().unwrap() = true;
    let device = fixture(&state);
    wait_until(|| state.received.load(Ordering::SeqCst) == 1);
    let shutdown = device.shutdown.clone();
    let closer = thread::spawn(move || drop(device));
    wait_until(|| shutdown.load(Ordering::SeqCst));
    // Let the in-flight receive/copy/release complete after Drop has begun.
    *state.hold_receive.lock().unwrap() = false;
    state.receive_gate.notify_all();
    closer.join().unwrap();
    assert_clean_shutdown(&state);
}
