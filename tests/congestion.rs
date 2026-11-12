use sfera::congestion::{ArrivalReport, Controller};
use std::time::Duration;

fn report(serial: u32, bytes: u64, packets: u64, seq: u16, arrival_ns: u64) -> ArrivalReport {
    ArrivalReport {
        serial,
        received_bytes: bytes,
        received_packets: packets,
        last_sequence: seq,
        arrival_ns,
    }
}

#[test]
fn report_wire_payload_is_fixed_length_and_validates_reserved_bytes() -> anyhow::Result<()> {
    let source = report(42, 123_456, 17, 0xABCD, 987_654_321);
    let payload = source.encode();
    assert_eq!(payload.len(), 32);
    assert_eq!(ArrivalReport::decode(42, &payload)?, source);

    let mut bad = payload.clone();
    bad[20] = 1;
    assert!(ArrivalReport::decode(42, &bad).is_err());
    assert!(ArrivalReport::decode(42, &payload[..31]).is_err());
    Ok(())
}

fn queue_sample_with_offset(offset_ns: u64) -> anyhow::Result<f64> {
    let mut controller = Controller::new(20.0, 20.0)?;
    controller.on_sent(1, Duration::ZERO, 1200);
    assert!(controller.on_feedback(
        &report(1, 1200, 1, 1, offset_ns + 40_000_000),
        Duration::from_millis(80),
    )?);
    controller.on_sent(2, Duration::from_millis(100), 1200);
    assert!(controller.on_feedback(
        &report(2, 2400, 2, 2, offset_ns + 150_000_000),
        Duration::from_millis(180),
    )?);
    Ok(controller.queue_delay_ms())
}

#[test]
fn queue_delay_cancels_unknown_receiver_clock_offset() -> anyhow::Result<()> {
    let no_offset = queue_sample_with_offset(0)?;
    let large_offset = queue_sample_with_offset(9_000_000_000_000)?;
    assert!((no_offset - 10.0).abs() < 0.001);
    assert!((large_offset - no_offset).abs() < 0.001);
    Ok(())
}

#[test]
fn persistent_queue_pressure_reduces_rate_to_delivered_capacity() -> anyhow::Result<()> {
    let mut controller = Controller::new(100.0, 100.0)?;
    for seq in 0..100u16 {
        controller.on_sent(seq, Duration::ZERO, 12_500);
    }
    assert!(controller.on_feedback(
        &report(1, 1_250_000, 100, 99, 40_000_000),
        Duration::from_millis(80),
    )?);

    for seq in 100..200u16 {
        controller.on_sent(seq, Duration::from_millis(100), 12_500);
    }
    assert!(controller.on_feedback(
        &report(2, 1_350_000, 101, 199, 150_000_000),
        Duration::from_millis(180),
    )?);
    assert!(controller.queue_delay_ms() >= 8.0);
    let reduced = controller.rate_mbps(Duration::from_millis(180));
    assert!(reduced < 100.0);
    // The fast 10% delay step must not mask a measured ~7 Mbps capacity.
    assert!(
        reduced <= 8.0,
        "capacity collapse remained hidden: {reduced}"
    );
    assert!(reduced >= 0.01);
    Ok(())
}

#[test]
fn sustained_queue_delay_triggers_bounded_fast_backoff() -> anyhow::Result<()> {
    let mut controller = Controller::new(20.0, 100.0)?;
    let mut sequence = 0u16;
    let mut received_bytes = 0u64;
    let mut received_packets = 0u64;

    // Establish a 40 ms minimum transit, then sustain 3 ms of extra delay
    // while offering about 100 Mbps. The delay signal should cause one
    // bounded fast backoff per control interval without a capacity collapse.
    for _ in 0..100 {
        sequence = sequence.wrapping_add(1);
        controller.on_sent(sequence, Duration::ZERO, 12_500);
    }
    received_bytes += 1_250_000;
    received_packets += 100;
    assert!(controller.on_feedback(
        &report(1, received_bytes, received_packets, sequence, 40_000_000),
        Duration::from_millis(80),
    )?);

    for interval in 1..=6u64 {
        let sent_at = Duration::from_millis(interval * 100);
        for _ in 0..100 {
            sequence = sequence.wrapping_add(1);
            controller.on_sent(sequence, sent_at, 12_500);
        }
        received_bytes += 1_250_000;
        received_packets += 100;
        assert!(controller.on_feedback(
            &report(
                interval as u32 + 1,
                received_bytes,
                received_packets,
                sequence,
                sent_at.as_nanos() as u64 + 43_000_000,
            ),
            sent_at + Duration::from_millis(80),
        )?);
    }

    assert!((controller.queue_delay_ms() - 3.0).abs() < 0.001);
    let backed_off = controller.rate_mbps(Duration::from_millis(680));
    assert!(
        backed_off < 12.0,
        "sustained delay was ignored: {backed_off}"
    );
    assert!(backed_off > 0.01);
    Ok(())
}

#[test]
fn app_limited_feedback_does_not_apply_absolute_delivery_ceiling() -> anyhow::Result<()> {
    let mut controller = Controller::new(100.0, 100.0)?;
    controller.on_sent(1, Duration::ZERO, 1200);
    assert!(controller.on_feedback(
        &report(1, 1200, 1, 1, 40_000_000),
        Duration::from_millis(80),
    )?);

    // Offered traffic is only 0.8 Mbps, while the deliberately sparse receive
    // counter reports about 0.007 Mbps. The last packet's 10 ms queue delay
    // still permits the ordinary fast delay response, but must not make the
    // low delivered rate an absolute capacity ceiling for an app-limited flow.
    for seq in 2..=11 {
        controller.on_sent(seq, Duration::from_millis(100), 1000);
    }
    assert!(controller.on_feedback(
        &report(2, 1300, 2, 11, 150_000_000),
        Duration::from_millis(180),
    )?);

    assert!((controller.rate_mbps(Duration::from_millis(180)) - 85.0).abs() < 0.001);
    Ok(())
}

#[test]
fn clean_feedback_grows_toward_desired_rate() -> anyhow::Result<()> {
    let mut controller = Controller::new(2.0, 20.0)?;
    controller.on_sent(1, Duration::ZERO, 25_000);
    assert!(controller.on_feedback(
        &report(1, 25_000, 1, 1, 40_000_000),
        Duration::from_millis(80),
    )?);
    controller.on_sent(2, Duration::from_millis(100), 25_000);
    assert!(controller.on_feedback(
        &report(2, 50_000, 2, 2, 140_000_000),
        Duration::from_millis(180),
    )?);
    assert!(controller.rate_mbps(Duration::from_millis(180)) > 2.0);
    assert!(controller.rate_mbps(Duration::from_millis(180)) <= 20.0);
    Ok(())
}

#[test]
fn queued_bulk_growth_uses_application_backlog_when_pacer_limits_rate() -> anyhow::Result<()> {
    let mut controller = Controller::new(10.0, 20.0)?;
    controller.on_sent(1, Duration::ZERO, 1200);
    assert!(controller.on_feedback(
        &report(1, 1200, 1, 1, 40_000_000),
        Duration::from_millis(80),
    )?);

    // The application has bulk queued, but the pacer only submits 5 Mbps,
    // below the 85% utilization inference threshold for the current 10 Mbps.
    controller.set_application_backlogged(true);
    controller.on_sent(2, Duration::from_millis(100), 62_500);
    assert!(controller.on_feedback(
        &report(2, 63_700, 2, 2, 140_000_000),
        Duration::from_millis(180),
    )?);
    assert!(controller.rate_mbps(Duration::from_millis(180)) > 10.0);
    Ok(())
}

#[test]
fn explicit_app_idle_hint_suppresses_growth_even_with_backlogged_network_rate() -> anyhow::Result<()>
{
    let mut controller = Controller::new(10.0, 20.0)?;
    controller.on_sent(1, Duration::ZERO, 1200);
    assert!(controller.on_feedback(
        &report(1, 1200, 1, 1, 40_000_000),
        Duration::from_millis(80),
    )?);

    // The measured send rate would imply a full sender, but the application
    // explicitly reports that it has no queued bulk data.
    controller.set_application_backlogged(false);
    controller.on_sent(2, Duration::from_millis(100), 250_000);
    assert!(controller.on_feedback(
        &report(2, 251_200, 2, 2, 140_000_000),
        Duration::from_millis(180),
    )?);
    assert_eq!(controller.rate_mbps(Duration::from_millis(180)), 10.0);
    Ok(())
}

#[test]
fn clean_backlogged_startup_keeps_fast_growth_after_three_seconds() -> anyhow::Result<()> {
    const PACKET_BYTES: usize = 1200;
    const PACKETS_PER_INTERVAL: u16 = 1042;

    let mut controller = Controller::new(1.0, 100.0)?;
    let mut serial = 0u32;
    let mut sequence = 0u16;
    let mut received_bytes = 0u64;
    let mut received_packets = 0u64;
    let mut rate_after_three_seconds = 0.0;

    // Offer roughly 100 Mbps continuously for twelve seconds with a stable
    // 40 ms one-way transit and no added queueing delay.
    for interval in 0..=120u64 {
        let sent_at = Duration::from_millis(interval * 100);
        for _ in 0..PACKETS_PER_INTERVAL {
            sequence = sequence.wrapping_add(1);
            controller.on_sent(sequence, sent_at, PACKET_BYTES);
        }
        received_bytes += u64::from(PACKETS_PER_INTERVAL) * PACKET_BYTES as u64;
        received_packets += u64::from(PACKETS_PER_INTERVAL);
        serial += 1;

        assert!(controller.on_feedback(
            &report(
                serial,
                received_bytes,
                received_packets,
                sequence,
                sent_at.as_nanos() as u64 + 40_000_000,
            ),
            sent_at + Duration::from_millis(80),
        )?);

        if interval == 30 {
            rate_after_three_seconds = controller.rate_mbps(sent_at + Duration::from_millis(80));
        }
    }

    let final_rate = controller.rate_mbps(Duration::from_millis(12080));
    assert!(rate_after_three_seconds > 1.0);
    assert!(final_rate > rate_after_three_seconds);
    assert_eq!(final_rate, 100.0);
    Ok(())
}

#[test]
fn one_percent_loss_does_not_trigger_congestion_backoff() -> anyhow::Result<()> {
    let mut controller = Controller::new(10.0, 20.0)?;
    for seq in 0..100u16 {
        controller.on_sent(seq, Duration::ZERO, 1_000);
    }
    controller.on_feedback(
        &report(1, 100_000, 100, 99, 40_000_000),
        Duration::from_millis(80),
    )?;
    for seq in 100..200u16 {
        controller.on_sent(seq, Duration::from_millis(100), 1_000);
    }
    controller.on_feedback(
        &report(2, 199_000, 199, 199, 140_000_000),
        Duration::from_millis(180),
    )?;
    assert!(controller.rate_mbps(Duration::from_millis(180)) >= 10.0);
    Ok(())
}

#[test]
fn stale_duplicate_and_out_of_history_feedback_are_ignored() -> anyhow::Result<()> {
    let mut controller = Controller::new(1.0, 10.0)?;
    controller.on_sent(7, Duration::ZERO, 1200);
    let first = report(10, 1200, 1, 7, 40_000_000);
    assert!(controller.on_feedback(&first, Duration::from_millis(80))?);
    assert!(!controller.on_feedback(&first, Duration::from_millis(90))?);
    assert!(!controller.on_feedback(
        &report(9, 1200, 1, 7, 50_000_000),
        Duration::from_millis(100),
    )?);
    assert!(!controller.on_feedback(
        &report(11, 1200, 1, 99, 140_000_000),
        Duration::from_millis(180),
    )?);
    assert_eq!(controller.feedback_updates(), 1);
    Ok(())
}

#[test]
fn forged_feedback_counters_above_sent_totals_are_rejected() -> anyhow::Result<()> {
    let mut controller = Controller::new(1.0, 10.0)?;
    controller.on_sent(7, Duration::ZERO, 1200);
    let forged = report(1, 2400, 2, 7, 40_000_000);
    assert!(
        controller
            .on_feedback(&forged, Duration::from_millis(80))
            .is_err()
    );
    assert_eq!(controller.feedback_updates(), 0);
    Ok(())
}

#[test]
fn send_history_is_bounded_and_timeout_falls_back_exponentially() -> anyhow::Result<()> {
    let mut controller = Controller::new(8.0, 20.0)?;
    for seq in 0..9000usize {
        controller.on_sent(seq as u16, Duration::ZERO, 1200);
    }
    assert_eq!(controller.history_len(), 8192);
    assert!(!controller.on_feedback(
        &report(1, 1200, 1, 0, 40_000_000),
        Duration::from_millis(80),
    )?);

    assert_eq!(controller.rate_mbps(Duration::from_millis(499)), 8.0);
    assert_eq!(controller.rate_mbps(Duration::from_millis(600)), 4.0);
    assert_eq!(controller.rate_mbps(Duration::from_millis(1100)), 2.0);
    Ok(())
}

#[test]
fn millisecond_arrival_jitter_does_not_collapse_an_uncongested_sender() -> anyhow::Result<()> {
    let mut controller = Controller::new(2.0, 20.0)?;
    controller.set_application_backlogged(true);
    for i in 0..100u16 {
        let sent = Duration::from_millis(i as u64 * 20);
        controller.on_sent(i, sent, 5000);
        let jitter = if i % 2 == 0 { 0 } else { 1_300_000 };
        controller.on_feedback(
            &report(
                i as u32 + 1,
                (i as u64 + 1) * 5000,
                i as u64 + 1,
                i,
                sent.as_nanos() as u64 + 20_000_000 + jitter,
            ),
            sent + Duration::from_millis(42),
        )?;
        assert!(controller.rate_mbps(sent + Duration::from_millis(42)) >= 2.0);
    }
    Ok(())
}

#[test]
fn in_flight_future_sends_do_not_look_like_delivery_loss() -> anyhow::Result<()> {
    let mut controller = Controller::new(10.0, 20.0)?;
    controller.set_application_backlogged(true);
    controller.on_sent(1, Duration::ZERO, 125_000);
    controller.on_feedback(
        &report(1, 125_000, 1, 1, 20_000_000),
        Duration::from_millis(80),
    )?;
    controller.on_sent(2, Duration::from_millis(100), 125_000);
    // New data left after the reported packet, before its feedback returned.
    controller.on_sent(3, Duration::from_millis(120), 4_000_000);
    controller.on_feedback(
        &report(2, 250_000, 2, 2, 120_000_000),
        Duration::from_millis(180),
    )?;
    assert!(controller.rate_mbps(Duration::from_millis(180)) > 10.0);
    Ok(())
}

#[test]
fn rising_delay_freezes_growth_before_the_queue_exceeds_target() -> anyhow::Result<()> {
    let mut controller = Controller::new(10.0, 20.0)?;
    controller.set_application_backlogged(true);
    for i in 0..=4u16 {
        let sent = Duration::from_millis(i as u64 * 10);
        controller.on_sent(i, sent, 12_500);
        controller.on_feedback(
            &report(
                i as u32 + 1,
                (i as u64 + 1) * 12_500,
                i as u64 + 1,
                i,
                sent.as_nanos() as u64 + 20_000_000 + i as u64 * 300_000,
            ),
            sent + Duration::from_millis(40),
        )?;
    }
    assert_eq!(controller.rate_mbps(Duration::from_millis(80)), 10.0);
    Ok(())
}
