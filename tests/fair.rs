use sfera::fair::FairQueue;
use std::time::Duration;

#[test]
fn five_backlogged_clients_receive_equal_byte_service() {
    let mut queue = FairQueue::new(5, 64 * 100, 5 * 64 * 100, 128).unwrap();
    for client in 0..5 {
        for _ in 0..100 {
            assert!(queue.push(client, vec![client as u8; 64], Duration::ZERO));
        }
    }

    let mut bytes = [0usize; 5];
    for _ in 0..50 {
        let packet = queue.pop(Duration::from_millis(10)).unwrap();
        bytes[packet.client] += packet.payload.len();
    }
    assert!(
        bytes.iter().all(|&n| n == bytes[0]),
        "service bytes: {bytes:?}"
    );
}

#[test]
fn noisy_client_limits_do_not_block_a_light_clients_queue() {
    let mut queue = FairQueue::new(2, 4, 8, 1).unwrap();
    for _ in 0..4 {
        assert!(queue.push(0, vec![0], Duration::ZERO));
    }
    assert!(!queue.push(0, vec![0], Duration::ZERO));
    assert!(queue.push(1, vec![1; 4], Duration::ZERO));
    assert_eq!(queue.queued_bytes(), 8);
    assert_eq!(queue.dropped_packets(), 1);
    assert_eq!(queue.per_client_drops(), vec![1, 0]);

    let mut light_client_served = false;
    for _ in 0..8 {
        if queue.pop(Duration::ZERO).unwrap().client == 1 {
            light_client_served = true;
            break;
        }
    }
    assert!(light_client_served);
}

#[test]
fn byte_and_packet_limits_reject_without_exceeding_bounds() {
    let mut bytes = FairQueue::new(2, 4, 5, 2).unwrap();
    assert!(bytes.push(0, vec![0; 4], Duration::ZERO));
    assert!(!bytes.push(0, vec![0; 1], Duration::ZERO)); // Per-client cap.
    assert!(bytes.push(1, vec![1], Duration::ZERO));
    assert!(!bytes.push(1, vec![1], Duration::ZERO)); // Global cap.
    assert_eq!(bytes.queued_bytes(), 5);
    assert_eq!(bytes.peak_bytes(), 5);
    assert_eq!(bytes.dropped_packets(), 2);

    let mut packets = FairQueue::new(1, 2048, 2048, 1).unwrap();
    for _ in 0..1024 {
        assert!(packets.push(0, vec![1], Duration::ZERO));
    }
    assert!(!packets.push(0, vec![1], Duration::ZERO));
    assert_eq!(packets.queued_bytes(), 1024);
    assert_eq!(packets.dropped_packets(), 1);

    assert!(!packets.push(0, Vec::new(), Duration::ZERO));
    assert!(!packets.push(4, vec![1], Duration::ZERO));
    assert_eq!(packets.per_client_drops(), vec![2]);
}

#[test]
fn empty_client_leaves_ring_and_can_reactivate_later() {
    let mut queue = FairQueue::new(2, 100, 100, 10).unwrap();
    assert!(queue.push(1, vec![7; 5], Duration::from_millis(3)));
    let packet = queue.pop(Duration::from_millis(8)).unwrap();
    assert_eq!(packet.client, 1);
    assert_eq!(packet.queued_for, Duration::from_millis(5));
    assert_eq!(queue.queued_bytes(), 0);
    assert!(queue.pop(Duration::from_millis(8)).is_none());

    assert!(queue.push(1, vec![8; 5], Duration::from_millis(10)));
    let packet = queue.pop(Duration::from_millis(12)).unwrap();
    assert_eq!(packet.payload, vec![8; 5]);
    assert_eq!(packet.queued_for, Duration::from_millis(2));
}

#[test]
fn unequal_packet_sizes_get_equal_drr_byte_quanta() {
    let mut queue = FairQueue::new(2, 2000, 4000, 100).unwrap();
    for _ in 0..10 {
        assert!(queue.push(0, vec![0; 100], Duration::ZERO));
    }
    for _ in 0..40 {
        assert!(queue.push(1, vec![1; 25], Duration::ZERO));
    }

    let mut served = [0usize; 2];
    for _ in 0..5 {
        let packet = queue.pop(Duration::ZERO).unwrap();
        served[packet.client] += packet.payload.len();
    }
    assert_eq!(served, [100, 100]);
}

#[test]
fn large_packet_with_small_quantum_does_not_spin_per_round() {
    let mut queue = FairQueue::new(1, 100_000, 100_000, 1).unwrap();
    assert!(queue.push(0, vec![1; 100_000], Duration::ZERO));
    assert_eq!(queue.pop(Duration::ZERO).unwrap().payload.len(), 100_000);
}
