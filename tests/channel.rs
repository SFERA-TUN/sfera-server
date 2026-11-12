use sfera::lab::LinkScheduler;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

fn destination() -> SocketAddr {
    "127.0.0.1:9".parse().unwrap()
}

#[test]
fn unshaped_channel_delivers_immediately_without_changing_payload_accounting() {
    let mut channel = LinkScheduler::new(0.0, 100).unwrap();
    let payload = vec![0x5a; 1300];
    let result = channel.enqueue(
        Instant::now(),
        destination(),
        payload.clone(),
        Duration::ZERO,
        false,
    );
    let (address, sent) = result.unwrap();
    assert_eq!(address, destination());
    assert_eq!(sent.len(), 1300); // UDP payload bytes, excluding IP/UDP headers.
    assert_eq!(channel.overflow_packets, 0);
    assert_eq!(channel.overflow_bytes, 0);
}

#[test]
fn scheduler_serializes_each_datagram_at_the_configured_payload_rate() {
    let now = Instant::now();
    let mut channel = LinkScheduler::new(1.0, 100).unwrap();
    assert!(
        channel
            .enqueue(now, destination(), vec![1; 1000], Duration::ZERO, false)
            .is_none()
    );
    let first_delivery = channel.next_delivery().unwrap();
    assert_eq!(first_delivery.duration_since(now), Duration::from_millis(8));
    assert!(
        channel
            .enqueue(now, destination(), vec![2; 1000], Duration::ZERO, false)
            .is_none()
    );
    assert_eq!(channel.pop_due(first_delivery).unwrap().1.len(), 1000);
    let second_delivery = channel.next_delivery().unwrap();
    assert_eq!(
        second_delivery.duration_since(first_delivery),
        Duration::from_millis(8)
    );
    assert_eq!(channel.pop_due(second_delivery).unwrap().1.len(), 1000);
}

#[test]
fn queue_budget_accounts_overflow_by_udp_payload_bytes() {
    let now = Instant::now();
    let mut channel = LinkScheduler::new(0.1, 100).unwrap();
    assert!(
        channel
            .enqueue(now, destination(), vec![0; 1000], Duration::ZERO, false)
            .is_none()
    );
    assert!(
        channel
            .enqueue(now, destination(), vec![0; 1000], Duration::ZERO, false)
            .is_none()
    );
    assert!(
        channel
            .enqueue(now, destination(), vec![0; 1000], Duration::ZERO, false)
            .is_none()
    );
    assert_eq!(channel.overflow_packets, 1);
    assert_eq!(channel.overflow_bytes, 1000);
}

#[test]
fn queue_ms_bounds_waiting_latency_even_when_minimum_packet_budget_applies() {
    let now = Instant::now();
    let mut channel = LinkScheduler::new(1.0, 1).unwrap();
    assert!(
        channel
            .enqueue(now, destination(), vec![0; 1000], Duration::ZERO, false)
            .is_none()
    );
    // The first packet takes 8 ms to serialize; a second packet would wait longer
    // than the configured 1 ms queue budget and is dropped.
    assert!(
        channel
            .enqueue(now, destination(), vec![1; 1000], Duration::ZERO, false)
            .is_none()
    );
    assert_eq!(channel.overflow_packets, 1);
    assert_eq!(channel.overflow_bytes, 1000);
}

#[test]
fn propagation_delay_does_not_consume_serialization_queue_budget() {
    let now = Instant::now();
    let mut channel = LinkScheduler::new(1.0, 1).unwrap();
    assert!(
        channel
            .enqueue(
                now,
                destination(),
                vec![0; 1000],
                Duration::from_millis(20),
                false
            )
            .is_none()
    );
    let finish = now + Duration::from_millis(8);
    assert!(channel.pop_due(finish).is_none()); // transmitted; still propagating
    assert!(
        channel
            .enqueue(
                finish,
                destination(),
                vec![1; 1000],
                Duration::from_millis(20),
                false
            )
            .is_none()
    );
    assert_eq!(channel.overflow_packets, 0);
    assert_eq!(channel.transmitted_bytes, 1000);
    // A second and third serialization must progress while packet one is still
    // propagating; checking only the delivery queue's front would block them.
    let second_finish = now + Duration::from_millis(16);
    assert!(channel.pop_due(second_finish).is_none());
    assert_eq!(channel.transmitted_bytes, 2000);
    assert!(
        channel
            .enqueue(
                second_finish,
                destination(),
                vec![2; 1000],
                Duration::from_millis(20),
                false
            )
            .is_none()
    );
    assert!(channel.pop_due(now + Duration::from_millis(24)).is_none());
    assert_eq!(channel.transmitted_bytes, 3000);
    assert_eq!(channel.overflow_packets, 0);
}

#[test]
fn injected_rtp_loss_counts_after_link_serialization() {
    let now = Instant::now();
    let mut channel = LinkScheduler::new(1.0, 100).unwrap();
    assert!(
        channel
            .enqueue(now, destination(), vec![0; 1000], Duration::ZERO, true)
            .is_none()
    );
    assert!(channel.pop_due(now + Duration::from_millis(7)).is_none());
    assert_eq!(channel.transmitted_bytes, 0);
    assert!(channel.pop_due(now + Duration::from_millis(8)).is_none());
    assert_eq!(channel.transmitted_bytes, 1000);
    assert_eq!(channel.rtp_drops, 1);
}
