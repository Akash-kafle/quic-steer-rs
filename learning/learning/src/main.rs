use anyhow::Context as _;
use aya::{
    maps::{RingBuf, Array},
    programs::{Xdp, XdpMode},
};
use clap::Parser;
use learning_common::NormalizedPacket;
use log::{info, warn};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "ens3")]
    iface: String,

    #[clap(short, long, use_value_delimiter = true)]
    skip_ips: Vec<Ipv4Addr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    // Set default log filter to "info" if RUST_LOG is not explicitly set
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load eBPF program
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/learning"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = match logger.readable_mut().await {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Attach XDP program
    let program: &mut Xdp = ebpf.program_mut("learning").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpMode::Skb)
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    info!("Successfully loaded and attached XDP program to interface: {}", opt.iface);

    let skip_ips: HashSet<Ipv4Addr> = opt.skip_ips.into_iter().collect();

    // Stream normalized packet records from ring buffer
    if let Some(map) = ebpf.take_map("RING_BUFF") {
        let ring_buf = RingBuf::try_from(map)?;
        let mut async_fd = tokio::io::unix::AsyncFd::new(ring_buf)?;
        tokio::task::spawn(async move {
            loop {
                let mut guard = match async_fd.readable_mut().await {
                    Ok(g) => g,
                    Err(_) => break,
                };
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() >= std::mem::size_of::<NormalizedPacket>() {
                        let packet = unsafe { *(item.as_ptr() as *const NormalizedPacket) };
                        let src_ip = Ipv4Addr::from(u32::to_le(packet.src_ip));
                        let dst_ip = Ipv4Addr::from(u32::to_le(packet.dst_ip));

                        if skip_ips.contains(&src_ip) || skip_ips.contains(&dst_ip) {
                            continue;
                        }

                        let proto_str = match packet.protocol {
                            6 => "TCP",
                            17 => "UDP",
                            _ => "OTHER",
                        };
                        info!(
                            "[RING_BUF] Proto: {} ({}) | Src: {}:{} -> Dst: {}:{} | Payload: {} bytes",
                            proto_str,
                            packet.protocol,
                            src_ip,
                            packet.src_port,
                            dst_ip,
                            packet.dst_port,
                            packet.payload_len
                        );
                    }
                }
                guard.clear_ready();
            }
        });
    }

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    // Print drop/pass counters from the eBPF map
    if let Some(map) = ebpf.map("COUNTERS") {
        if let Ok(counters) = Array::<_, u64>::try_from(map) {
            let passes = counters.get(&0, 0).unwrap_or(0);
            let drops = counters.get(&1, 0).unwrap_or(0);
            info!("Stats — passed: {}  dropped: {}", passes, drops);
        }
    }

    Ok(())
}

