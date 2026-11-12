//! Bounded per-client egress queues scheduled with deficit round robin.
use anyhow::{Result, ensure};
use std::{collections::VecDeque, time::Duration};

const MAX_CLIENTS: usize = 4096;
const MAX_PACKETS_TOTAL: usize = 4096;
const MAX_PACKETS_PER_CLIENT: usize = 1024;

struct QueuedPacket {
    payload: Vec<u8>,
    enqueued_at: Duration,
}

struct ClientQueue {
    packets: VecDeque<QueuedPacket>,
    queued_bytes: usize,
    deficit: usize,
    drops: u64,
}

/// A packet released by the fair scheduler.
#[derive(Debug, PartialEq, Eq)]
pub struct FairPacket {
    pub client: usize,
    pub payload: Vec<u8>,
    pub queued_for: Duration,
}

/// Per-client queues with byte caps, packet caps, and DRR byte fairness.
pub struct FairQueue {
    clients: Vec<ClientQueue>,
    active: VecDeque<usize>,
    /// The client currently consuming its accumulated DRR deficit.
    current: Option<usize>,
    per_client_limit: usize,
    total_limit: usize,
    total_bytes: usize,
    peak_bytes: usize,
    total_packets: usize,
    total_drops: u64,
    quantum: usize,
}

impl FairQueue {
    pub fn new(
        clients: usize,
        per_client_bytes: usize,
        total_bytes: usize,
        quantum: usize,
    ) -> Result<Self> {
        ensure!(
            clients > 0 && clients <= MAX_CLIENTS,
            "clients must be 1..=4096"
        );
        ensure!(
            per_client_bytes > 0,
            "per-client byte limit must be positive"
        );
        ensure!(total_bytes > 0, "total byte limit must be positive");
        ensure!(quantum > 0, "DRR quantum must be positive");
        Ok(Self {
            clients: (0..clients)
                .map(|_| ClientQueue {
                    packets: VecDeque::new(),
                    queued_bytes: 0,
                    deficit: 0,
                    drops: 0,
                })
                .collect(),
            active: VecDeque::new(),
            current: None,
            per_client_limit: per_client_bytes,
            total_limit: total_bytes,
            total_bytes: 0,
            peak_bytes: 0,
            total_packets: 0,
            total_drops: 0,
            quantum,
        })
    }

    /// Adds a packet if byte and packet limits permit it.
    /// Returns false for invalid clients, empty payloads, or a full queue.
    pub fn push(&mut self, client: usize, payload: Vec<u8>, now: Duration) -> bool {
        if client >= self.clients.len() {
            self.total_drops = self.total_drops.saturating_add(1);
            return false;
        }
        let size = payload.len();
        let queue = &self.clients[client];
        if size == 0
            || queue.queued_bytes.saturating_add(size) > self.per_client_limit
            || self.total_bytes.saturating_add(size) > self.total_limit
            || queue.packets.len() >= MAX_PACKETS_PER_CLIENT
            || self.total_packets >= MAX_PACKETS_TOTAL
        {
            self.drop_for(client);
            return false;
        }

        let was_empty = self.clients[client].packets.is_empty();
        let queue = &mut self.clients[client];
        queue.queued_bytes += size;
        queue.packets.push_back(QueuedPacket {
            payload,
            enqueued_at: now,
        });
        self.total_bytes += size;
        self.total_packets += 1;
        self.peak_bytes = self.peak_bytes.max(self.total_bytes);
        if was_empty && self.current != Some(client) {
            self.active.push_back(client);
        }
        true
    }

    /// Returns the next eligible packet, preserving DRR deficit across visits.
    pub fn pop(&mut self, now: Duration) -> Option<FairPacket> {
        if self.active.is_empty() && self.current.is_none() {
            return None;
        }
        let ring_len = self.active.len() + usize::from(self.current.is_some());
        let mut skipped = 0;

        loop {
            if self.current.is_none() {
                let client = self.active.pop_front()?;
                self.clients[client].deficit =
                    self.clients[client].deficit.saturating_add(self.quantum);
                self.current = Some(client);
            }

            let client = self.current.expect("current client was selected");
            let Some(packet_len) = self.clients[client]
                .packets
                .front()
                .map(|packet| packet.payload.len())
            else {
                self.clients[client].deficit = 0;
                self.current = None;
                continue;
            };

            if packet_len <= self.clients[client].deficit {
                let packet = self.clients[client]
                    .packets
                    .pop_front()
                    .expect("front packet checked");
                let size = packet.payload.len();
                let queue = &mut self.clients[client];
                queue.deficit -= size;
                queue.queued_bytes -= size;
                self.total_bytes -= size;
                self.total_packets -= 1;
                if queue.packets.is_empty() {
                    // DRR discards unused credit when a client becomes idle.
                    queue.deficit = 0;
                    self.current = None;
                }
                return Some(FairPacket {
                    client,
                    payload: packet.payload,
                    queued_for: now.saturating_sub(packet.enqueued_at),
                });
            }

            self.active.push_back(client);
            self.current = None;
            skipped += 1;
            if skipped == ring_len {
                skipped = 0;
                self.accrue_rounds_until_eligible();
            }
        }
    }

    pub fn queued_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn peak_bytes(&self) -> usize {
        self.peak_bytes
    }

    pub fn dropped_packets(&self) -> u64 {
        self.total_drops
    }

    pub fn per_client_drops(&self) -> Vec<u64> {
        self.clients.iter().map(|queue| queue.drops).collect()
    }

    fn drop_for(&mut self, client: usize) {
        self.total_drops = self.total_drops.saturating_add(1);
        self.clients[client].drops = self.clients[client].drops.saturating_add(1);
    }

    /// All clients failed to send in one complete round. Skip whole rounds
    /// arithmetically so a large packet with a small quantum cannot spin CPU.
    fn accrue_rounds_until_eligible(&mut self) {
        let extra_rounds = self
            .active
            .iter()
            .filter_map(|&client| {
                let queue = &self.clients[client];
                let size = queue.packets.front()?.payload.len();
                let missing = size.saturating_sub(queue.deficit);
                Some(missing.div_ceil(self.quantum).saturating_sub(1))
            })
            .min()
            .unwrap_or(0);
        if extra_rounds == 0 {
            return;
        }
        let credit = self.quantum.saturating_mul(extra_rounds);
        for &client in &self.active {
            self.clients[client].deficit = self.clients[client].deficit.saturating_add(credit);
        }
    }
}
