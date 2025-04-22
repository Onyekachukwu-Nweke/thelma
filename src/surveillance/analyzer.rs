// HTLC analysis algorithms for surveillance

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

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
        let network = self.network.lock().unwrap();

        // Get timelock analysis
        let timelock_analysis = htlc.timelock_analysis();

        // For each malicious node, find potential destinations
        let mut potential_recipients = Vec::new();
        let observed_node = htlc.observed_by_node.clone();

        // Get the max reasonable number of hops to search
        let max_hops = timelock_analysis.max_remaining_hops;

        // Find possible routes with the remaining budget
        let routes = network.find_possible_routes_with_budget(
            &observed_node,
            timelock_analysis.remaining_cltv_budget,
            max_hops);

        // Log the analysis
        println!("HTLC Analysis for hash {}", htlc.payment_hash);
        println!("  Remaining CLTV budget: {}", timelock_analysis.remaining_cltv_budget);
        println!("  Estimated hops remaining: up to {}", max_hops);
        println!("  Potential final hop: {}", timelock_analysis.could_be_final_hop);
        println!("  Found {} potential routes from node {}", routes.len(), observed_node);

        // Calculate confidence scores and create PotentialRecipient objects
        for route in routes {
            // The last node in the route is the potential recipient
            if let Some(recipient) = route.last() {
                // Create a PotentialRecipient with confidence score
                if let Some(node) = network.nodes.get(recipient) {
                    let alias = Some(node.alias.clone());

                    // Calculate a confidence score based on route length, timelock, etc.
                    // This is a simplified heuristic - real attackers would have more sophisticated methods
                    let confidence = self.calculate_confidence_score(&route, &timelock_analysis);

                    potential_recipients.push(PotentialRecipient {
                        node_id: recipient.clone(),
                        node_alias: alias,
                        route: route.clone(),
                        confidence_score: confidence,
                    });

                    println!("  Potential recipient: {} with confidence {:.2}",
                             node.alias, confidence);
                }
            }
        }

        // Sort by confidence score
        potential_recipients.sort_by(|a, b| b.confidence_score.partial_cmp(&a.confidence_score).unwrap());

        potential_recipients
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
    fn calculate_confidence_score(&self, route: &[String], analysis: &TimelockAnalysis) -> f32 {
        let network = self.network.lock().unwrap();

        // Base confidence based on remaining CLTV budget
        let mut confidence = 1.0;

        // Confidence decreases with route length - shorter routes are more likely
        confidence *= 1.0 / (route.len() as f32).powf(0.5);

        // If the timelock analysis suggests this is a final hop, increase confidence
        if analysis.could_be_final_hop && route.len() <= 2 {
            confidence *= 1.5;
        }

        // Check if the destination node's CLTV delta is close to DEFAULT_FINAL_CLTV_DELTA
        if let Some(recipient) = route.last() {
            if let Some(node) = network.nodes.get(recipient) {
                let delta_diff = (node.cltv_expiry_delta as i32 - DEFAULT_FINAL_CLTV_DELTA as i32).abs();
                if delta_diff <= 5 {
                    confidence *= 1.3;  // Node uses standard CLTV delta, more likely
                }
            }
        }

        // Check for logical consistency in the route
        let mut consistent = true;
        for i in 0..route.len() - 1 {
            let from_node = &route[i];
            let to_node = &route[i + 1];

            // Check if there's an actual channel between these nodes
            if let Some(neighbors) = network.get_neighbors(from_node) {
                if !neighbors.contains(&to_node.to_string()) {
                    consistent = false;
                    break;
                }
            } else {
                consistent = false;
                break;
            }
        }

        if !consistent {
            confidence *= 0.1;  // Heavily penalize inconsistent routes
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