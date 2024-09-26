use color_eyre::eyre::Result;
use filesnoop_bpf::FilesnoopSkelBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use log::{error, info};
use std::mem::MaybeUninit;
use std::time::Duration;

mod filesnoop_bpf {
    include!(concat!(env!("OUT_DIR"), "/filesnoop.skel.rs"));
}

fn main() -> Result<()> {
    color_eyre::install()?;
    simple_logger::init()?;

    info!("Setting up eBPF program...");

    let mut obj = MaybeUninit::uninit();
    let skel_builder = FilesnoopSkelBuilder::default();
    let open_skel = skel_builder.open(&mut obj)?;
    let mut skel = open_skel.load()?;

    let mut builder = RingBufferBuilder::new();
    builder.add(&mut skel.maps.open_events, open_events_handler)?;
    let ringbuf = builder.build()?;

    skel.attach()?;
    while ringbuf.poll(Duration::MAX).is_ok() {}

    Ok(())
}

fn open_events_handler(data: &[u8]) -> i32 {
    if data.len() != std::mem::size_of::<OpenEvent>() {
        error!(
            "Invalid size {} != {}",
            data.len(),
            std::mem::size_of::<OpenEvent>()
        );
        return 1;
    }

    let event = unsafe { &*(data.as_ptr() as *const OpenEvent) };

    let filename = std::str::from_utf8(&event.filename).unwrap_or("<unknown>");
    info!(
        "filename: {filename}; pid={}; ppid={}; exit_code={}",
        event.pid, event.ppid, event.exit_code
    );
    0
}

const MAX_FILENAME_LEN: usize = 255;

#[repr(C)]
struct OpenEvent {
    ts: u64,
    filename: [u8; MAX_FILENAME_LEN],
    pid: i32,
    ppid: i32,
    exit_code: u32,
}
