use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sfera::{
    lab::{self, DEFAULT_ACK_EVERY, DEFAULT_WINDOW_BLOCKS, Options},
    media::{Clip, MAX_FILE},
    wire::MAX_DATA,
};
use std::{io::Read, path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    version,
    about = "SFERA experimental media transport laboratory (loopback only)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Measure concurrent sessions over a shared fair loopback bottleneck.
    Multi {
        #[arg(long)]
        ivf: Option<PathBuf>,
        #[arg(long, default_value_t = 5)]
        clients: usize,
        #[arg(long, default_value_t = 8388608)]
        bytes: usize,
        #[arg(long, default_value_t = 100.0)]
        link_mbps: f64,
        #[arg(long, default_value_t = 20)]
        queue_ms: u64,
        #[arg(long, default_value_t = 20)]
        one_way_delay_ms: u64,
        #[arg(long, default_value_t = 90)]
        timeout_secs: u64,
        /// Aggregate admitted packet rate divided by shared capacity.
        #[arg(long, default_value_t = 0.95)]
        offered_load: f64,
        /// Last client sends only interactive probes; remaining clients bulk data.
        #[arg(long)]
        interactive_last: bool,
        /// First client offers four times its share (isolation stress test).
        #[arg(long)]
        greedy_first: bool,
        #[arg(long, default_value_t = 0)]
        drop_every: u64,
        /// Disable feedback-driven admission (control experiment only).
        #[arg(long)]
        static_rate: bool,
        /// Compare against str0m TWCC instead of the arrival-feedback controller.
        #[arg(long, conflicts_with = "static_rate")]
        native_cc: bool,
        /// Sender startup estimate, independent of the modeled channel rate.
        #[arg(long, default_value_t = 5.0)]
        initial_mbps: f64,
        #[arg(long, default_value_t = 0)]
        min_duration_secs: u64,
        /// Change shared capacity at SECONDS:MBPS; may be repeated.
        #[arg(long, value_parser = parse_capacity_step)]
        capacity_step: Vec<lab::multi::CapacityStep>,
        #[arg(long, default_value_t = 0.0)]
        random_loss_pct: f64,
        #[arg(long, default_value_t = 1)]
        loss_seed: u64,
        #[arg(long, default_value_t = 0)]
        burst_every: u64,
        #[arg(long, default_value_t = 0)]
        burst_len: u64,
        #[arg(long, default_value_t = 100)]
        probe_deadline_ms: u64,
    },
    /// Exchange independent reliable data + unreliable probes over SRTP video.
    Lab {
        /// VP8 IVF input; defaults to the bundled generated test clip.
        #[arg(long)]
        ivf: Option<PathBuf>,
        /// Reliable payload bytes in EACH direction.
        #[arg(long, default_value_t = 262144)]
        bytes: usize,
        /// Reliable data block size (1..=wire maximum).
        #[arg(long, default_value_t = MAX_DATA)]
        block_size: usize,
        /// Reliable selective-repeat window (power of two, 32..=4096 blocks).
        #[arg(long, default_value_t = DEFAULT_WINDOW_BLOCKS)]
        window_blocks: usize,
        /// Coalesce ACKs after this many data blocks (timer still limits delay).
        #[arg(long, default_value_t = DEFAULT_ACK_EVERY)]
        ack_every: usize,
        /// Drop every Nth encrypted RTP packet per peer (0 = disabled).
        #[arg(long, default_value_t = 0)]
        drop_every: u64,
        /// Corrupt every Nth SRTP packet per peer (0 = disabled).
        #[arg(long, default_value_t = 0)]
        tamper_every: u64,
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Artificial one-way network delay (0..1000 ms), including handshake.
        #[arg(long, default_value_t = 0)]
        one_way_delay_ms: u64,
        /// Configured UDP-payload link capacity per direction (0 or 0.01..=10000 Mbps).
        #[arg(long, default_value_t = 0.0)]
        link_mbps: f64,
        /// Bounded queue budget at the configured rate (1..10000 ms).
        #[arg(long, default_value_t = 100)]
        queue_ms: u64,
        /// Fixed reliable retransmission timeout in milliseconds (10..5000; default: adaptive).
        #[arg(long)]
        fixed_rto_ms: Option<u64>,
        /// Send the unchanged clip for this many seconds as a control run.
        #[arg(long)]
        cover_only_secs: Option<u64>,
    },
}

fn main() -> Result<()> {
    let command = Cli::parse().command;
    if let Command::Multi {
        ivf,
        clients,
        bytes,
        link_mbps,
        queue_ms,
        one_way_delay_ms,
        timeout_secs,
        offered_load,
        interactive_last,
        greedy_first,
        drop_every,
        static_rate,
        native_cc,
        initial_mbps,
        min_duration_secs,
        capacity_step,
        random_loss_pct,
        loss_seed,
        burst_every,
        burst_len,
        probe_deadline_ms,
    } = command
    {
        anyhow::ensure!(
            random_loss_pct.is_finite() && (0.0..=25.0).contains(&random_loss_pct),
            "random-loss-pct must be 0..25"
        );
        let clip = read_clip(ivf)?;
        let report = lab::multi::run(
            &clip,
            &Options {
                bytes,
                link_mbps,
                queue_ms,
                one_way_delay: Duration::from_millis(one_way_delay_ms),
                timeout: Duration::from_secs(timeout_secs),
                drop_every,
                ..Options::default()
            },
            &lab::multi::MultiOptions {
                clients,
                offered_load,
                interactive_last,
                greedy_first,
                adaptive: !static_rate,
                native_cc,
                initial_mbps,
                min_duration: Duration::from_secs(min_duration_secs),
                capacity_steps: capacity_step,
                random_loss_ppm: (random_loss_pct * 10000.0).round() as u32,
                loss_seed,
                burst_every,
                burst_len,
                probe_deadline: Duration::from_millis(probe_deadline_ms),
            },
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    let Command::Lab {
        ivf,
        bytes,
        block_size,
        window_blocks,
        ack_every,
        drop_every,
        tamper_every,
        timeout_secs,
        one_way_delay_ms,
        link_mbps,
        queue_ms,
        fixed_rto_ms,
        cover_only_secs,
    } = command
    else {
        unreachable!()
    };
    let clip = read_clip(ivf)?;
    let report = lab::run(
        &clip,
        &Options {
            bytes,
            block_size,
            window_blocks,
            ack_every,
            drop_every,
            tamper_every,
            timeout: Duration::from_secs(timeout_secs),
            one_way_delay: Duration::from_millis(one_way_delay_ms),
            link_mbps,
            queue_ms,
            fixed_rto: fixed_rto_ms.map(Duration::from_millis),
            cover_only: cover_only_secs.map(Duration::from_secs),
            bwe_initial_mbps: None,
            arrival_initial_mbps: None,
        },
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_capacity_step(value: &str) -> std::result::Result<lab::multi::CapacityStep, String> {
    let (seconds, mbps) = value.split_once(':').ok_or("expected SECONDS:MBPS")?;
    let seconds: f64 = seconds.parse().map_err(|_| "invalid seconds")?;
    let mbps: f64 = mbps.parse().map_err(|_| "invalid Mbps")?;
    if !seconds.is_finite()
        || !(0.0..=300.0).contains(&seconds)
        || !mbps.is_finite()
        || !(0.1..=1000.0).contains(&mbps)
    {
        return Err("step requires seconds 0..300 and Mbps 0.1..1000".into());
    }
    Ok(lab::multi::CapacityStep {
        after: Duration::from_secs_f64(seconds),
        mbps,
    })
}

fn read_clip(ivf: Option<PathBuf>) -> Result<Clip> {
    let data = if let Some(path) = ivf {
        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .with_context(|| format!("opening {}", path.display()))?
            .take((MAX_FILE + 1) as u64)
            .read_to_end(&mut bytes)?;
        bytes
    } else {
        include_bytes!("../fixtures/cover-vp8.ivf").to_vec()
    };
    Clip::parse(&data)
}
