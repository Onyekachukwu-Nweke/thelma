// Simulation of Lightning Network payments for surveillance testing

use std::sync::{Arc, Mutex};
use std::error::Error;
use rand::Rng;
use tokio::time::{sleep, Duration};

use crate::models::{HTLC, LightningNetworkMap};
use crate::models::htlc::{DEFAULT_FINAL_CLTV_DELTA, CLTV_RANDOM_OFFSET_MIN, CLTV_RANDOM_OFFSET_MAX};
use crate::surveillance::SurveillanceOperation;
use crate::simulation::utils::generate_random_path;

// Payment simulator for testing surveillance capabilities
pub struct PaymentSimulator {
    network: Arc<Mutex<LightningNetworkMap>>,
    rng: rand::rngs::ThreadRng,
    surveillance: Arc<Mutex<SurveillanceOperation>>,
    // Optional delay between simulated payments for more realistic behavior
    delay_ms: u64,
}

impl PaymentSimulator {
    pub fn new(network: Arc<Mutex<LightningNetworkMap>>,
               surveillance: Arc<Mutex<SurveillanceOperation>>,
               delay_ms: u64) -> Self {
        PaymentSimulator {
            network,
            rng: rand::rng(),
            surveillance,
            delay_ms,
        }
    }

    // Simulate a single payment through the network
    pub async fn simulate_payment(&mut self) -> Result<bool, Box<dyn Error>> {
        // Get current network state
        let network = self.network.lock().unwrap();
        let current_height = network.current_block_height;

        // Get all node pubkeys
        let node_keys: Vec<String> = network.nodes.keys().cloned().collect();
        drop(network); // Release the lock

        if node_keys.len() < 2 {
            return Err("Not enough nodes in the network".into());
        }

        // Pick random sender and receiver
        let sender_idx = self.rng.random_range(0..node_keys.len());
        let mut receiver_idx = self.rng.random_range(0..node_keys.len());
        while receiver_idx == sender_idx {
            receiver_idx = self.rng.random_range(0..node_keys.len());
        }

        let sender = &node_keys[sender_idx];
        let receiver = &node_keys[receiver_idx];

        println!("Simulating payment from {} to {}", sender, receiver);

        // Generate a random path between them
        let path = generate_random_path(self.network.clone(), sender, receiver)?;

        if path.len() < 2 {
            println!("  Couldn't find path, skipping payment");
            return Ok(false);
        }

        println!("  Found path with {} hops", path.len() - 1);

        // Create a unique payment hash
        let payment_hash = format!("hash_{:016x}", self.rng.random()::<u64>());
        let amount = self.rng.random_range(10000..1000000); // Random amount in millisatoshis

        // Add random offset for privacy
        let random_offset = self.rng.random_range(CLTV_RANDOM_OFFSET_MIN..CLTV_RANDOM_OFFSET_MAX);

        // Calculate the final CLTV expiry
        let mut final_cltv_expiry = current_height + DEFAULT_FINAL_CLTV_DELTA + random_offset;

        // Add CLTV deltas for each hop
        let mut cltv_expiry_values = Vec::new();
        let mut accumulated_delta = 0;

        // Simulate CLTV values for each hop (in reverse)
        for node_pubkey in path.iter().rev().skip(1) {
            let network = self.network.lock().unwrap();
            let delta = match network.nodes.get(node_pubkey) {
                Some(node) => node.cltv_expiry_delta,
                None => 14, // Minimum if unknown
            };
            drop(network);

            accumulated_delta += delta;
            cltv_expiry_values.push(final_cltv_expiry + accumulated_delta);
        }

        // Reverse to match the forward path
        cltv_expiry_values.reverse();

        // Add final value
        cltv_expiry_values.push(final_cltv_expiry);

        // Now simulate the HTLC being observed by malicious nodes
        let surveillance = self.surveillance.lock().unwrap();
        let malicious_nodes = surveillance.get_malicious_nodes().to_vec();
        drop(surveillance);

        let mut observed = false;

        for (i, node) in path.iter().enumerate() {
            if malicious_nodes.contains(node) {
                let cltv_expiry = cltv_expiry_values[i];

                let htlc = HTLC::new(
                    &payment_hash,
                    cltv_expiry,
                    amount,
                    current_height,
                    node
                );

                // Record the observation
                let mut surveillance = self.surveillance.lock().unwrap();
                surveillance.record_htlc_observation(htlc);
                drop(surveillance);

                println!("  Malicious node {} observed HTLC!", node);
                observed = true;
            }
        }

        // Simulate some time passing between payments if delay is set
        if self.delay_ms > 0 {
            sleep(Duration::from_millis(self.delay_ms)).await;
        }

        Ok(observed)
    }

    // Simulate multiple payments
    pub async fn simulate_payments(&mut self, count: usize) -> Result<usize, Box<dyn Error>> {
        let mut observed_count = 0;

        for i in 0..count {
            println!("Simulating payment {}/{}", i+1, count);

            if let Ok(observed) = self.simulate_payment().await {
                if observed {
                    observed_count += 1;
                }
            }
        }

        println!("Simulated {} payments, {} were observed by surveillance nodes",
                 count, observed_count);

        Ok(observed_count)
    }

    // Update the current block height (to simulate time passing)
    pub fn advance_block_height(&mut self, blocks: u32) {
        let mut network = self.network.lock().unwrap();
        network.current_block_height += blocks;
        println!("Advanced block height by {}. New height: {}",
                 blocks, network.current_block_height);
    }

    // Simulate a specific payment between two nodes
    pub async fn simulate_specific_payment(&mut self,
                                           from_node: &str,
                                           to_node: &str) -> Result<bool, Box<dyn Error>> {
        // Get current network state
        let network = self.network.lock().unwrap();
        let current_height = network.current_block_height;

        // Verify both nodes exist
        if !network.nodes.contains_key(from_node) || !network.nodes.contains_key(to_node) {
            drop(network);
            return Err("One or both specified nodes don't exist in the network".into());
        }
        drop(network);

        println!("Simulating specific payment from {} to {}", from_node, to_node);

        // Generate a path between them
        let path = generate_random_path(self.network.clone(), from_node, to_node)?;

        if path.len() < 2 {
            println!("  Couldn't find path, skipping payment");
            return Ok(false);
        }

        println!("  Found path with {} hops", path.len() - 1);

        // Create a unique payment hash
        let payment_hash = format!("hash_{:016x}", self.rng.random()::<u64>());
        let amount = self.rng.random_range(10000..1000000); // Random amount in millisatoshis

        // Add random offset for privacy
        let random_offset = self.rng.random_range(CLTV_RANDOM_OFFSET_MIN..CLTV_RANDOM_OFFSET_MAX);

        // Calculate the final CLTV expiry
        let mut final_cltv_expiry = current_height + DEFAULT_FINAL_CLTV_DELTA + random_offset;

        // Add CLTV deltas for each hop
        let mut cltv_expiry_values = Vec::new();
        let mut accumulated_delta = 0;

        // Simulate CLTV values for each hop (in reverse)
        for node_pubkey in path.iter().rev().skip(1) {
            let network = self.network.lock().unwrap();
            let delta = match network.nodes.get(node_pubkey) {
                Some(node) => node.cltv_expiry_delta,
                None => 14, // Minimum if unknown
            };
            drop(network);

            accumulated_delta += delta;
            cltv_expiry_values.push(final_cltv_expiry + accumulated_delta);
        }

        // Reverse to match the forward path
        cltv_expiry_values.reverse();

        // Add final value
        cltv_expiry_values.push(final_cltv_expiry);

        // Now simulate the HTLC being observed by malicious nodes
        let surveillance = self.surveillance.lock().unwrap();
        let malicious_nodes = surveillance.get_malicious_nodes().to_vec();
        drop(surveillance);

        let mut observed = false;

        for (i, node) in path.iter().enumerate() {
            if malicious_nodes.contains(node) {
                let cltv_expiry = cltv_expiry_values[i];

                let htlc = HTLC::new(
                    &payment_hash,
                    cltv_expiry,
                    amount,
                    current_height,
                    node
                );

                // Record the observation
                let mut surveillance = self.surveillance.lock().unwrap();
                surveillance.record_htlc_observation(htlc);
                drop(surveillance);

                println!("  Malicious node {} observed HTLC!", node);
                observed = true;
            }
        }

        // Simulate some time passing between payments if delay is set
        if self.delay_ms > 0 {
            sleep(Duration::from_millis(self.delay_ms)).await;
        }

        Ok(observed)
    }
}
