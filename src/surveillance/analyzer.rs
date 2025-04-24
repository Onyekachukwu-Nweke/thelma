// HTLC analysis algorithms for surveillance

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use rayon::prelude::*;
use log::log;
use crate::models::{HTLC, LightningNetworkMap, TimelockAnalysis, DEFAULT_FINAL_CLTV_DELTA};

// Result of surveillance analysis for a potential recipient
#[derive(Debug, Clone)]
pub struct PotentialRecipient {
    pub node_id: String,
    pub node_alias: Option<String>,
    pub route: Vec<String>,
    pub confidence_score: f32,
}

// Core HTLC analysis functionality
pub struct HTLCAnalyzer {
    network: Arc<Mutex<LightningNetworkMap>>,
}

impl HTLCAnalyzer {
    pub fn new(network: Arc<Mutex<LightningNetworkMap>>) -> Self {
        HTLCAnalyzer { network }
    }

    // Analyze a specific HTLC observation to determine potential recipients
    pub fn analyze_htlc(&self, htlc: &HTLC) -> Vec<PotentialRecipient> {
        log::info!("Analyzing HTLC");
        let network = self.network.lock().unwrap();

        let timelock_analysis = htlc.timelock_analysis();
        let observed_node = htlc.observed_by_node.clone();
        let max_hops = timelock_analysis.max_remaining_hops;

        let routes = network.find_possible_routes_with_budget(
            &observed_node,
            timelock_analysis.remaining_cltv_budget,
            max_hops,
        );

        println!("HTLC Analysis for hash {}", htlc.payment_hash);
        println!("  Remaining CLTV budget: {}", timelock_analysis.remaining_cltv_budget);
        println!("  Estimated hops remaining: up to {}", max_hops);
        println!("  Potential final hop: {}", timelock_analysis.could_be_final_hop);
        println!("  Found {} potential routes from node {}", routes.len(), observed_node);

        let potential_recipients: Vec<PotentialRecipient> = routes
            .par_iter()
            .filter_map(|route| {
                if let Some(recipient) = route.last() {
                    network.nodes.get(recipient).map(|node| {
                        let confidence = Self::calculate_confidence_score(route, &timelock_analysis, &network);
                        println!("  Potential recipient: {} with confidence {:.2}", node.alias, confidence);
                        PotentialRecipient {
                            node_id: recipient.clone(),
                            node_alias: Some(node.alias.clone()),
                            route: route.clone(),
                            confidence_score: confidence,
                        }
                    })
                } else {
                    None
                }
            })
            .collect();

        let mut sorted_recipients = potential_recipients;
        sorted_recipients.sort_by(|a, b| b.confidence_score.partial_cmp(&a.confidence_score).unwrap());
        sorted_recipients
    }

    // Correlate observations from multiple malicious nodes to narrow down senders/recipients
    pub fn correlate_observations(&self, observations: &[HTLC]) -> HashMap<String, Vec<PotentialRecipient>> {
        let mut payment_hash_map: HashMap<String, Vec<HTLC>> = HashMap::new();

        // Group observations by payment hash
        for htlc in observations {
            payment_hash_map.entry(htlc.payment_hash.clone())
                .or_insert_with(Vec::new)
                .push(htlc.clone());
        }

        let mut results = HashMap::new();

        // For each payment hash, correlate observations
        for (payment_hash, observations) in payment_hash_map {
            if observations.len() < 2 {
                println!("Only one observation for payment hash {}, insufficient for correlation", payment_hash);

                // We can still analyze single observations
                if let Some(htlc) = observations.first() {
                    let recipients = self.analyze_htlc(htlc);
                    if !recipients.is_empty() {
                        results.insert(payment_hash, recipients);
                    }
                }

                continue;
            }

            println!("Correlating {} observations for payment hash {}", observations.len(), payment_hash);

            // Sort by CLTV expiry to establish order in the route
            let mut sorted_obs = observations.clone();
            sorted_obs.sort_by_key(|htlc| htlc.cltv_expiry);

            // Analyze the last observation (closest to recipient)
            if let Some(last_obs) = sorted_obs.last() {
                println!("Analyzing last observation in route for payment hash {}", payment_hash);
                // Analyze for potential recipients
                let potential_recipients = self.analyze_htlc(last_obs);

                if !potential_recipients.is_empty() {
                    // Store the results
                    results.insert(payment_hash, potential_recipients);
                }
            }
        }

        results
    }

    // Calculate a confidence score for a potential route
    fn calculate_confidence_score(
        route: &[String],
        analysis: &TimelockAnalysis,
        network: &LightningNetworkMap,
    ) -> f32 {
        // Base confidence starts at 1.0
        let mut confidence = 1.0;

        // Penalize longer routes (prefer shorter)
        confidence *= 1.0 / (route.len() as f32).powf(0.5);

        // Boost if could be final hop and route is short
        if analysis.could_be_final_hop && route.len() <= 2 {
            confidence *= 1.5;
        }

        // Check if final node has standard CLTV delta
        if let Some(recipient) = route.last() {
            if let Some(node) = network.nodes.get(recipient) {
                let delta_diff = (node.cltv_expiry_delta as i32 - DEFAULT_FINAL_CLTV_DELTA as i32).abs();
                if delta_diff <= 5 {
                    confidence *= 1.3;
                }
            }
        }

        // Penalize route if links are not consistent
        let mut consistent = true;
        for i in 0..route.len().saturating_sub(1) {
            let from = &route[i];
            let to = &route[i + 1];

            if let Some(neighbors) = network.get_neighbors(from) {
                if !neighbors.contains(to) {
                    consistent = false;
                    break;
                }
            } else {
                consistent = false;
                break;
            }
        }

        if !consistent {
            confidence *= 0.1;
        }

        confidence
    }


    // Try to backtrack from an observation to find potential senders
    pub fn backtrack_potential_senders(&self, htlc: &HTLC) -> Vec<String> {
        // This is more complex in reality, but for demonstration we'll do a simple implementation
        let network = self.network.lock().unwrap();
        let observed_node = &htlc.observed_by_node;

        // Get direct neighbors as potential previous hops
        let mut potential_senders = Vec::new();

        if let Some(neighbors) = network.get_neighbors(observed_node) {
            for neighbor in neighbors {
                // In a real attack, you would filter based on more sophisticated heuristics
                potential_senders.push(neighbor.clone());
            }
        }

        potential_senders
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Node, Channel};

    #[test]
    fn test_htlc_analysis() {
        // Create a test network
        let network_map = Arc::new(Mutex::new(LightningNetworkMap::new(700000)));

        println!("Creating test network");

        {
            let mut network = network_map.lock().unwrap();

            // Add nodes
            let nodes = vec![
                Node::new("node1", "Node 1", 20),
                Node::new("node2", "Node 2", 20),
                Node::new("node3", "Node 3", 40), // Final node with standard delta
            ];

            for node in nodes {
                network.add_node(node);
            }

            // Connect in a line
            network.add_channel(Channel::new("chan1", "node1", "node2", 1000000));
            network.add_channel(Channel::new("chan2", "node2", "node3", 1000000));
        }

        let analyzer = HTLCAnalyzer::new(network_map);

        // Create an HTLC observation that suggests it's on the way to node3
        let htlc = HTLC::new(
            "test_hash",
            700080,  // expiry: enough for node2 -> node3 with standard delta
            100000,
            700000,
            "node2"  // observed at node2
        );

        let recipients = analyzer.analyze_htlc(&htlc);

        println!("recipients");

        // We should identify node3 as a potential recipient
        assert!(!recipients.is_empty());
        assert_eq!(recipients[0].node_id, "node3");
        assert!(recipients[0].confidence_score > 0.5);
    }
}