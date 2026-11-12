//! Bounded TUN read-ahead with packet round robin between inner flows.
use super::CongestionMode;
use std::collections::{HashMap, VecDeque};

const STAGE_PACKETS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct InnerFlow {
    addresses: [u8; 8],
    protocol: u8,
    ports: Option<[u8; 4]>,
}

impl InnerFlow {
    fn for_packet(packet: &[u8]) -> Option<Self> {
        let header = usize::from(packet[0] & 0xf) * 4;
        let protocol = packet[9];
        if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
            return None;
        }
        let ports = if matches!(protocol, 6 | 17) {
            Some(packet.get(header..header + 4)?.try_into().ok()?)
        } else {
            None
        };
        Some(Self {
            addresses: packet[12..20].try_into().expect("validated IPv4 header"),
            protocol,
            ports,
        })
    }
}

struct StagedIp {
    order: u64,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct FlowQueues {
    len: usize,
    next_order: u64,
    flows: HashMap<InnerFlow, VecDeque<StagedIp>>,
    ready: VecDeque<InnerFlow>,
}

enum Queue {
    Single(Option<Vec<u8>>),
    Fifo(VecDeque<Vec<u8>>),
    Flows(FlowQueues),
}

pub(super) struct StagedPackets {
    queue: Queue,
}

impl StagedPackets {
    pub(super) fn new(mode: CongestionMode) -> Self {
        let queue = match mode {
            CongestionMode::IpTunnel => Queue::Flows(FlowQueues::default()),
            CongestionMode::NativeTwcc | CongestionMode::ArrivalFeedback => Queue::Single(None),
        };
        Self { queue }
    }

    pub(super) fn reads_per_visit(&self) -> usize {
        if matches!(self.queue, Queue::Single(_)) {
            1
        } else {
            8
        }
    }

    pub(super) fn len(&self) -> usize {
        match &self.queue {
            Queue::Single(packet) => usize::from(packet.is_some()),
            Queue::Fifo(queue) => queue.len(),
            Queue::Flows(queues) => queues.len,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(super) fn is_full(&self) -> bool {
        match &self.queue {
            Queue::Single(packet) => packet.is_some(),
            _ => self.len() == STAGE_PACKETS,
        }
    }

    pub(super) fn push(&mut self, packet: Vec<u8>) {
        debug_assert!(!self.is_full());
        match &mut self.queue {
            Queue::Single(slot) => *slot = Some(packet),
            Queue::Fifo(queue) => queue.push_back(packet),
            Queue::Flows(queues) => {
                let Some(flow) = InnerFlow::for_packet(&packet) else {
                    // A fragment has no unambiguous transport key. Restore the
                    // remaining ingress order and stay FIFO for this session.
                    let mut pending: Vec<_> =
                        queues.flows.drain().flat_map(|(_, flow)| flow).collect();
                    pending.sort_unstable_by_key(|packet| packet.order);
                    let mut fifo: VecDeque<_> =
                        pending.into_iter().map(|packet| packet.bytes).collect();
                    fifo.push_back(packet);
                    self.queue = Queue::Fifo(fifo);
                    return;
                };
                let queue = queues.flows.entry(flow).or_insert_with(|| {
                    queues.ready.push_back(flow);
                    VecDeque::new()
                });
                queue.push_back(StagedIp {
                    order: queues.next_order,
                    bytes: packet,
                });
                queues.next_order += 1;
                queues.len += 1;
            }
        }
    }

    pub(super) fn front(&self) -> Option<&[u8]> {
        match &self.queue {
            Queue::Single(packet) => packet.as_deref(),
            Queue::Fifo(queue) => queue.front().map(Vec::as_slice),
            Queue::Flows(queues) => queues
                .ready
                .front()
                .and_then(|flow| queues.flows[flow].front())
                .map(|packet| packet.bytes.as_slice()),
        }
    }

    pub(super) fn pop(&mut self) -> Option<Vec<u8>> {
        match &mut self.queue {
            Queue::Single(packet) => packet.take(),
            Queue::Fifo(queue) => queue.pop_front(),
            Queue::Flows(queues) => {
                let flow = queues.ready.pop_front()?;
                let queue = queues.flows.get_mut(&flow).expect("ready flow exists");
                let packet = queue.pop_front().expect("ready flow has a packet");
                if queue.is_empty() {
                    queues.flows.remove(&flow);
                } else {
                    queues.ready.push_back(flow);
                }
                queues.len -= 1;
                Some(packet.bytes)
            }
        }
    }
}

#[cfg(test)]
mod flow_stage_tests {
    use super::*;

    fn packet(port: u16, serial: u8, fragment: u8) -> Vec<u8> {
        let mut bytes = vec![0; 44];
        bytes[0] = 0x45;
        bytes[6] = fragment;
        bytes[9] = 6;
        bytes[12..20].copy_from_slice(&[192, 0, 2, 2, 10, 203, 0, 2]);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        bytes[43] = serial;
        bytes
    }

    #[test]
    fn alternate_congestion_modes_stage_one_packet() {
        for mode in [CongestionMode::NativeTwcc, CongestionMode::ArrivalFeedback] {
            let mut stage = StagedPackets::new(mode);
            assert_eq!(stage.reads_per_visit(), 1);
            stage.push(packet(5201, 7, 0));
            assert!(stage.is_full());
            assert_eq!(stage.pop().unwrap()[43], 7);
            assert!(stage.is_empty());
        }
    }

    #[test]
    fn sparse_flow_passes_bulk_in_fifo_order_within_each_flow() {
        let mut stage = StagedPackets::new(CongestionMode::IpTunnel);
        for serial in 0..100 {
            stage.push(packet(5201, serial, 0));
        }
        stage.push(packet(5202, 200, 0));
        stage.push(packet(5202, 201, 0));
        let delivered: Vec<u8> = std::iter::from_fn(|| stage.pop().map(|p| p[43])).collect();
        assert_eq!(&delivered[..5], &[0, 200, 1, 201, 2]);
        assert_eq!(
            delivered
                .into_iter()
                .filter(|&n| n < 100)
                .collect::<Vec<_>>(),
            (0..100).collect::<Vec<_>>()
        );
        assert!(stage.is_empty());
    }

    #[test]
    fn ipv4_fragment_restores_fifo_for_staged_packets() {
        let mut stage = StagedPackets::new(CongestionMode::IpTunnel);
        stage.push(packet(5201, 0, 0));
        stage.push(packet(5201, 1, 0));
        stage.push(packet(5202, 2, 0));
        stage.push(packet(5201, 3, 0x20));
        stage.push(packet(5202, 4, 0));
        assert!(matches!(stage.queue, Queue::Fifo(_)));
        let delivered: Vec<u8> = std::iter::from_fn(|| stage.pop().map(|p| p[43])).collect();
        assert_eq!(delivered, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn staged_queue_releases_capacity_without_discarding_fifo_data() {
        for queue in [
            Queue::Fifo(VecDeque::new()),
            Queue::Flows(FlowQueues::default()),
        ] {
            let mut stage = StagedPackets { queue };
            for serial in 0..STAGE_PACKETS {
                assert!(!stage.is_full());
                stage.push(packet(5201, serial as u8, 0));
            }
            assert!(stage.is_full());
            for serial in 0..STAGE_PACKETS {
                assert_eq!(stage.pop().unwrap()[43], serial as u8);
            }
            assert!(stage.is_empty());
        }
    }
}
