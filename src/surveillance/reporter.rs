// Reporting functionality for surveillance results

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::fs::File;
use std::io::Write;
use std::error::Error;

use crate::models::LightningNetworkMap;
use crate::surveillance::analyzer::PotentialRecipient;

// Reporter for surveillance operation results
pub struct SurveillanceReporter {
    network: Arc<Mutex<LightningNetworkMap>>,
}

impl SurveillanceReporter {
    pub fn new(network: Arc<Mutex<LightningNetworkMap>>) -> Self {
        SurveillanceReporter { network }
    }

    // Generate a text report of surveillance results
    pub fn generate_text_report(&self, results: &HashMap<String, Vec<PotentialRecipient>>) -> String {
        let mut report = String::from("## THELMA: Lightning Network Surveillance Report\n\n");
        report.push_str(&format!("Total unique payments observed: {}\n\n", results.len()));

        for (payment_hash, recipients) in results {
            report.push_str(&format!("### Payment Hash: {}\n", payment_hash));
            report.push_str(&format!("Potential recipients identified: {}\n", recipients.len()));

            for (i, recipient) in recipients.iter().enumerate() {
                let node_name = match &recipient.node_alias {
                    Some(alias) => alias.clone(),
                    None => "Unknown Node".to_string(),
                };

                report.push_str(&format!("{}. {} ({}) - Confidence: {:.2}\n",
                                         i+1, node_name, recipient.node_id, recipient.confidence_score));

                // Add route information
                report.push_str("   Route: ");
                for (j, node) in recipient.route.iter().enumerate() {
                    if j > 0 {
                        report.push_str(" → ");
                    }

                    let network = self.network.lock().unwrap();
                    let node_alias = match network.nodes.get(node) {
                        Some(n) => n.alias.clone(),
                        None => node.clone(),
                    };

                    report.push_str(&node_alias);
                }
                report.push_str("\n");
            }
            report.push_str("\n");
        }

        report
    }

    // Save report to file
    pub fn save_report_to_file(&self, results: &HashMap<String, Vec<PotentialRecipient>>,
                               filename: &str) -> Result<(), Box<dyn Error>> {
        let report = self.generate_text_report(results);

        let mut file = File::create(filename)?;
        file.write_all(report.as_bytes())?;

        println!("Report saved to {}", filename);
        Ok(())
    }

    // Generate a JSON report
    pub fn generate_json_report(&self, results: &HashMap<String, Vec<PotentialRecipient>>) -> String {
        let mut report_data = serde_json::Map::new();

        report_data.insert("total_payments".to_string(),
                           serde_json::Value::Number(serde_json::Number::from(results.len())));

        let mut payments = serde_json::Map::new();

        for (payment_hash, recipients) in results {
            let mut payment_data = serde_json::Map::new();
            payment_data.insert("recipient_count".to_string(),
                                serde_json::Value::Number(serde_json::Number::from(recipients.len())));

            let mut recipients_data = Vec::new();

            for recipient in recipients {
                let mut recipient_data = serde_json::Map::new();

                recipient_data.insert("node_id".to_string(),
                                      serde_json::Value::String(recipient.node_id.clone()));

                if let Some(alias) = &recipient.node_alias {
                    recipient_data.insert("node_alias".to_string(),
                                          serde_json::Value::String(alias.clone()));
                }

                recipient_data.insert("confidence".to_string(),
                                      serde_json::Value::Number(
                                          serde_json::Number::from_f64(recipient.confidence_score as f64)
                                              .unwrap_or(serde_json::Number::from(0))));

                let route: Vec<serde_json::Value> = recipient.route.iter()
                    .map(|n| serde_json::Value::String(n.clone()))
                    .collect();

                recipient_data.insert("route".to_string(), serde_json::Value::Array(route));

                recipients_data.push(serde_json::Value::Object(recipient_data));
            }

            payment_data.insert("potential_recipients".to_string(),
                                serde_json::Value::Array(recipients_data));

            payments.insert(payment_hash.clone(), serde_json::Value::Object(payment_data));
        }

        report_data.insert("payments".to_string(), serde_json::Value::Object(payments));

        serde_json::to_string_pretty(&serde_json::Value::Object(report_data))
            .unwrap_or_else(|_| "Error generating JSON report".to_string())
    }
}
