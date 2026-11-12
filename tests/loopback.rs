use sfera::{
    lab::{self, Options},
    media::Clip,
};
use std::time::Duration;

fn clip() -> Clip {
    Clip::parse(include_bytes!("../fixtures/cover-vp8.ivf")).unwrap()
}

#[test]
fn encrypted_bidirectional_transfer_survives_loss() {
    let report = lab::run(
        &clip(),
        &Options {
            bytes: 32 * 1024,
            window_blocks: 2048,
            drop_every: 7,
            one_way_delay: Duration::from_millis(20),
            ..Options::default()
        },
    )
    .unwrap();
    assert!(report.integrity_verified);
    assert_eq!(report.received_bytes_each_direction, 32 * 1024);
    assert!(report.rtp_packets_dropped > 0);
    assert!(report.reliable_retransmissions > 0);
    assert!(report.datagram_rtt_samples > 0);
    assert!(report.datagram_rtt_p50_ms.unwrap() >= 40.0);
    assert_ne!(report.left_received_sha256, report.right_received_sha256);
}

#[test]
fn corrupted_srtp_cannot_deliver_application_data() {
    let result = lab::run(
        &clip(),
        &Options {
            bytes: 4096,
            tamper_every: 1,
            timeout: Duration::from_secs(2),
            ..Options::default()
        },
    );
    let error = result.unwrap_err().to_string();
    assert!(error.contains("connected=true"), "{error}");
    assert!(error.contains("received=0/0"), "{error}");
    assert!(error.contains("RTP received=0/0"), "{error}");
}
