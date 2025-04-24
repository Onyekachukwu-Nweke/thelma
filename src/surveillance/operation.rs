// Core surveillance operation logic

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::models::{HTLC, LightningNetworkMap};
use crate::surveillance::analyzer::{HTLCAnalyzer, PotentialRecipient};
use crate::surveillance::reporter::SurveillanceReporter;

// Structure for our malicious surveillance operation
pub struct SurveillanceOperation {
    network: Arc<Mutex<LightningNetworkMap>>,
    malicious_nodes: Vec<String>,
    observed_htlcs: Vec<HTLC>,
    analyzer: HTLCAnalyzer,
    reporter: SurveillanceReporter,
}

impl SurveillanceOperation {
    pub fn new(network: Arc<Mutex<LightningNetworkMap>>, malicious_nodes: Vec<String>) -> Self {
        SurveillanceOperation {
            analyzer: HTLCAnalyzer::new(network.clone()),
            reporter: SurveillanceReporter::new(network.clone()),
            network,
            malicious_nodes,
            observed_htlcs: Vec::new(),
        }
    }

    // Register malicious nodes for surveillance
    pub fn register_malicious_node(&mut self, node_id: &str) {
        if !self.malicious_nodes.contains(&node_id.to_string()) {
            println!("Registering node {} for surveillance", node_id);
            self.malicious_nodes.push(node_id.to_string());
        }
    }

    // Get list of malicious nodes
    pub fn get_malicious_nodes(&self) -> &[String] {
        &self.malicious_nodes
    }

    // Record an HTLC observation from one of our malicious nodes
    pub fn record_htlc_observation(&mut self, htlc: HTLC) {
        // Make sure it's from one of our nodes
        if self.malicious_nodes.contains(&htlc.observed_by_node) {
            println!("Malicious node {} observed HTLC: payment_hash={}, cltv={}, amount={}",
                     htlc.observed_by_node, htlc.payment_hash, htlc.cltv_expiry, htlc.amount);
            self.observed_htlcs.push(htlc);
        } else {
            println!("Ignoring HTLC from non-malicious node {}", htlc.observed_by_node);
        }
    }

    // Record multiple HTLC observations at once
    pub fn record_multiple_observations(&mut self, htlcs: Vec<HTLC>) {
        for htlc in htlcs {
            self.record_htlc_observation(htlc);
        }
    }

    // Get all recorded HTLC observations
    pub fn get_observations(&self) -> &[HTLC] {
        &self.observed_htlcs
    }

    // Analyze a specific HTLC
    pub fn analyze_single_htlc(&self, htlc: &HTLC) -> Vec<PotentialRecipient> {
        self.analyzer.analyze_htlc(htlc)
    }

    // Run surveillance analysis on all collected data
    pub fn run_analysis(&self) -> HashMap<String, Vec<PotentialRecipient>> {
        println!("Running surveillance analysis on {} observations", self.observed_htlcs.len());
        self.analyzer.correlate_observations(&self.observed_htlcs)
    }

    // Generate a surveillance report
    pub fn generate_report(&self) -> String {
        let results = self.run_analysis();
        self.reporter.generate_text_report(&results)
    }

    // Save a surveillance report to file
    pub fn save_report(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let results = self.run_analysis();
        self.reporter.save_report_to_file(&results, filename)
    }

    // Generate JSON format report
    pub fn generate_json_report(&self) -> String {
        let results = self.run_analysis();
        self.reporter.generate_json_report(&results)
    }

    // Clear all observations (for long-running operations)
    pub fn clear_observations(&mut self) {
        self.observed_htlcs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Node, Channel};

    #[test]
    fn test_record_observation() {
        // Create a test network
        let network_map = Arc::new(Mutex::new(LightningNetworkMap::new(700000)));

        {
            let mut network = network_map.lock().unwrap();
            network.add_node(Node::new("node1", "Node 1", 40));
            network.add_node(Node::new("node2", "Node 2", 40));
        }

        // Setup surveillance with node1 as malicious
        let mut surveillance = SurveillanceOperation::new(
            network_map,
            vec!["node1".to_string()]
        );

        // Create an HTLC observation from the malicious node
        let htlc = HTLC::new(
            "test_hash",
            700080,
            100000,
            700000,
            "node1"
        );

        // Test recording the observation
        surveillance.record_htlc_observation(htlc);
        assert_eq!(surveillance.get_observations().len(), 1);

        // Create an HTLC from a non-malicious node
        let htlc2 = HTLC::new(
            "test_hash2",
            700080,
            100000,
            700000,
            "node2"
        );

        // This should be ignored
        surveillance.record_htlc_observation(htlc2);
        assert_eq!(surveillance.get_observations().len(), 1);
    }
}
