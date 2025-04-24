// Helper for generating test Lightning Networks

use std::sync::{Arc, Mutex};
use std::error::Error;
use rand::Rng;

use crate::models::{Node, Channel, LightningNetworkMap};

// Network generator for simulations
pub struct NetworkGenerator {
    pub rng: rand::rngs::ThreadRng,
}

impl NetworkGenerator {
    pub fn new() -> Self {
        NetworkGenerator {
            rng: rand::rng(),
        }
    }

    // Create a simple test network with specified number of nodes
    pub fn create_simple_network(&mut self,
                                 network_map: Arc<Mutex<LightningNetworkMap>>,
                                 node_count: usize) -> Result<(), Box<dyn Error>> {
        let mut network = network_map.lock().unwrap();

        // Add nodes with reasonable CLTV deltas
        for i in 0..node_count {
            // Generate a random CLTV delta between 14 and 50
            let cltv_delta = if i % 5 == 0 {
                // Every 5th node has standard delta of 40
                40
            } else {
                self.rng.random_range(14..=50)
            };

            let node = Node::new(
                &format!("node{}", i+1),
                &format!("Node {}", i+1),
                cltv_delta
            );

            network.add_node(node);
        }

        println!("Created {} nodes", node_count);

        // Create a connected ring topology to ensure reachability
        for i in 0..node_count {
            let channel = Channel::new(
                &format!("chan{}", i+1),
                &format!("node{}", i+1),
                &format!("node{}", (i+1) % node_count + 1),
                1_000_000 + self.rng.random_range(0..5_000_000)
            );

            network.add_channel(channel);
        }

        // Add some random cross connections for a more realistic network
        let extra_channels = node_count / 2;
        for i in 0..extra_channels {
            let node1 = self.rng.random_range(1..=node_count);
            let mut node2 = self.rng.random_range(1..=node_count);

            // Ensure we don't connect a node to itself
            while node1 == node2 {
                node2 = self.rng.random_range(1..=node_count);
            }

            let channel = Channel::new(
                &format!("xchan{}", i+1),
                &format!("node{}", node1),
                &format!("node{}", node2),
                500_000 + self.rng.random_range(0..3_000_000)
            );

            network.add_channel(channel);
        }

        println!("Created {} channels", node_count + extra_channels);

        Ok(())
    }

    // Create a scale-free network using preferential attachment
    // This better models real-world network topologies where some nodes are hubs
    pub fn create_scale_free_network(&mut self,
                                     network_map: Arc<Mutex<LightningNetworkMap>>,
                                     node_count: usize,
                                     min_connections: usize) -> Result<(), Box<dyn Error>> {
        let mut network = network_map.lock().unwrap();

        // Add nodes
        for i in 0..node_count {
            let cltv_delta = match i % 10 {
                0 => 40,  // LND default
                1 => 34,  // Eclair default
                2 => 42,  // C-lightning default
                _ => self.rng.random_range(14..=50),
            };

            let node = Node::new(
                &format!("node{}", i+1),
                &format!("Node {}", i+1),
                cltv_delta
            );

            network.add_node(node);
        }

        println!("Created {} nodes", node_count);

        // If we have at least min_connections nodes, create initial fully-connected cluster
        let initial_nodes = std::cmp::min(node_count, min_connections);
        for i in 0..initial_nodes {
            for j in (i+1)..initial_nodes {
                let channel = Channel::new(
                    &format!("chan{}-{}", i+1, j+1),
                    &format!("node{}", i+1),
                    &format!("node{}", j+1),
                    1_000_000 + self.rng.random_range(0..5_000_000)
                );

                network.add_channel(channel);
            }
        }

        // Add remaining nodes using preferential attachment
        let mut channel_count = initial_nodes * (initial_nodes - 1) / 2;

        for i in initial_nodes..node_count {
            // Connect to min_connections existing nodes with probability proportional
            // to their current degree (number of connections)

            // Count connections for each existing node
            let mut connection_counts = Vec::new();
            for j in 0..i {
                let connections = network.adjacency_list[&format!("node{}", j+1)].len();
                connection_counts.push((j, connections));
            }

            // Sort by connection count (descending)
            connection_counts.sort_by(|a, b| b.1.cmp(&a.1));

            // Connect to the top min_connections nodes
            for k in 0..std::cmp::min(min_connections, i) {
                let j = connection_counts[k].0;

                let channel = Channel::new(
                    &format!("chan{}-{}", i+1, j+1),
                    &format!("node{}", i+1),
                    &format!("node{}", j+1),
                    500_000 + self.rng.random_range(0..3_000_000)
                );

                network.add_channel(channel);
                channel_count += 1;
            }
        }

        println!("Created {} channels", channel_count);

        Ok(())
    }

    // Select a random subset of nodes as malicious observers
    pub fn select_malicious_nodes(&mut self,
                                  network_map: Arc<Mutex<LightningNetworkMap>>,
                                  count: usize) -> Vec<String> {
        let network = network_map.lock().unwrap();
        let all_nodes: Vec<String> = network.nodes.keys().cloned().collect();

        // Select random nodes to be malicious
        let mut malicious_nodes = Vec::new();
        let mut indices: Vec<usize> = (0..all_nodes.len()).collect();

        // Shuffle indices
        for i in 0..indices.len() {
            let j = self.rng.random_range(i..indices.len());
            indices.swap(i, j);
        }

        // Select the first 'count' indices
        for i in 0..std::cmp::min(count, all_nodes.len()) {
            malicious_nodes.push(all_nodes[indices[i]].clone());
        }

        malicious_nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_network_generation() {
        let network_map = Arc::new(Mutex::new(LightningNetworkMap::new(700000)));
        let mut generator = NetworkGenerator::new();

        let node_count = 10;
        generator.create_simple_network(network_map.clone(), node_count).unwrap();

        let network = network_map.lock().unwrap();
        assert_eq!(network.nodes.len(), node_count);
        assert!(network.channels.len() >= node_count); // At least one channel per node
    }

    #[test]
    fn test_malicious_node_selection() {
        let network_map = Arc::new(Mutex::new(LightningNetworkMap::new(700000)));
        let mut generator = NetworkGenerator::new();

        // Create a network with 20 nodes
        generator.create_simple_network(network_map.clone(), 20).unwrap();

        // Select 5 malicious nodes
        let malicious_nodes = generator.select_malicious_nodes(network_map.clone(), 5);

        assert_eq!(malicious_nodes.len(), 5);

        // All nodes should be unique
        let mut unique_nodes = std::collections::HashSet::new();
        for node in &malicious_nodes {
            unique_nodes.insert(node);
        }

        assert_eq!(unique_nodes.len(), 5);
    }
}