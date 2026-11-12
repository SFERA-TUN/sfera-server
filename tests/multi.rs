use sfera::{
    lab::{
        Options,
        multi::{self, MultiOptions},
    },
    media::Clip,
};
use std::time::Duration;

#[test]
fn authenticated_arrival_feedback_controls_an_overloaded_shared_path() -> anyhow::Result<()> {
    let clip = Clip::parse(include_bytes!("../fixtures/cover-vp8.ivf"))?;
    let options = Options {
        bytes: 128 * 1024,
        link_mbps: 20.0,
        queue_ms: 20,
        one_way_delay: Duration::from_millis(5),
        timeout: Duration::from_secs(20),
        ..Options::default()
    };
    let report = multi::run(
        &clip,
        &options,
        &MultiOptions {
            clients: 5,
            offered_load: 2.0,
            initial_mbps: 10.0,
            ..MultiOptions::default()
        },
    )?;
    assert_eq!(report.controller, "arrival-delay-delivery-experimental");
    for client in &report.clients {
        assert!(client.integrity_verified);
        assert_eq!(client.received_bytes_each_direction, options.bytes);
        assert!(client.bwe_updates > 0, "no authenticated feedback accepted");
        assert!(client.probe_quality.replied > 0);
    }
    Ok(())
}

#[test]
fn five_encrypted_sessions_complete_through_shared_bounded_queues() -> anyhow::Result<()> {
    let clip = Clip::parse(include_bytes!("../fixtures/cover-vp8.ivf"))?;
    let options = Options {
        bytes: 64 * 1024,
        link_mbps: 20.0,
        queue_ms: 20,
        one_way_delay: Duration::from_millis(5),
        timeout: Duration::from_secs(15),
        ..Options::default()
    };
    let report = multi::run(
        &clip,
        &options,
        &MultiOptions {
            clients: 5,
            offered_load: 0.8,
            interactive_last: false,
            greedy_first: false,
            adaptive: false,
            ..MultiOptions::default()
        },
    )?;
    assert_eq!(report.clients.len(), 5);
    for client in &report.clients {
        assert!(client.integrity_verified);
        assert_eq!(client.received_bytes_each_direction, options.bytes);
        assert!(client.probe_samples > 0);
    }
    assert!(
        report
            .queue_peak_bytes_each_direction
            .iter()
            .all(|&peak| peak <= report.queue_budget_bytes_each_direction)
    );
    Ok(())
}

#[test]
fn twenty_sessions_deliver_bulk_and_real_control_echoes() -> anyhow::Result<()> {
    let clip = Clip::parse(include_bytes!("../fixtures/cover-vp8.ivf"))?;
    let options = Options {
        bytes: 32 * 1024,
        link_mbps: 100.0,
        queue_ms: 20,
        one_way_delay: Duration::from_millis(5),
        timeout: Duration::from_secs(30),
        ..Options::default()
    };
    let report = multi::run(
        &clip,
        &options,
        &MultiOptions {
            clients: 20,
            interactive_last: true,
            ..MultiOptions::default()
        },
    )?;
    assert!(report.compact_control_packets);
    assert_eq!(report.clients.len(), 20);
    for client in &report.clients {
        assert!(client.integrity_verified);
        assert_eq!(
            client.probe_requests as usize,
            client.probe_quality.generated
        );
        assert_eq!(client.probe_samples, client.probe_quality.replied);
        assert!(client.probe_samples > 0, "encrypted echo was not received");
    }
    assert!(
        report
            .queue_peak_bytes_each_direction
            .iter()
            .all(|&size| size <= report.queue_budget_bytes_each_direction)
    );
    Ok(())
}
