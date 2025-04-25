use std::sync::{Arc, Mutex};
use std::error::Error;
use std::env;

pub mod models;
pub mod surveillance;
pub mod simulation;

use models::LightningNetworkMap;
use surveillance::SurveillanceOperation;
use simulation::{NetworkGenerator, PaymentSimulator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting THELMA: Timelock Heuristic Evaluation for Lightning Movement Analysis");
    println!("==========================================================================");

    // Parse command line args
    let args: Vec<String> = env::args().collect();
    let (node_count, payment_count, malicious_count) = parse_args(&args);

    println!("Simulation parameters:");
    println!("  Network size:      {} nodes", node_count);
    println!("  Payments to sim:   {}", payment_count);
    println!("  Malicious nodes:   {}", malicious_count);

    // Initialize network with current block height
    let current_block_height = 780000;
    let network_map = Arc::new(Mutex::new(LightningNetworkMap::new(current_block_height)));

    // Create a simulated network
    println!("\nGenerating network topology...");
    let mut generator = NetworkGenerator::new();
    generator.create_scale_free_network(network_map.clone(), node_count, 3)?;

    // Select some nodes to be malicious observers
    println!("\nSelecting malicious surveillance nodes...");
    let malicious_nodes = generator.select_malicious_nodes(network_map.clone(), malicious_count);

    println!("Malicious nodes:");
    for node in &malicious_nodes {
        let network = network_map.lock().unwrap();
        let alias = match network.nodes.get(node) {
            Some(n) => n.alias.clone(),
            None => "Unknown".to_string(),
        };
        println!("  • {} ({})", alias, node);
    }

    // Initialize surveillance operation
    let surveillance = Arc::new(Mutex::new(
        SurveillanceOperation::new(network_map.clone(), malicious_nodes)
    ));

    // Run the simulation
    println!("\nSimulating {} Lightning payments...", payment_count);
    let mut simulator = PaymentSimulator::new(network_map.clone(), surveillance.clone(), 50);
    let observed = simulator.simulate_payments(payment_count).await?;

    println!("\nSimulation complete. {}/{} payments observed by surveillance nodes.",
             observed, payment_count);

    // Generate and print the report
    println!("\nGenerating surveillance analysis report...");
    let surveillance = surveillance.lock().unwrap();
    let report = surveillance.generate_report();

    println!("\n{}", report);

    // Save the report to a file
    surveillance.save_report("thelma_report.md")?;

    // Also save as JSON for programmatic use
    let json_report = surveillance.generate_json_report();
    std::fs::write("thelma_report.json", json_report)?;

    println!("\nReports saved to thelma_report.md and thelma_report.json");

    Ok(())
}

// Parse command line arguments with sensible defaults
fn parse_args(args: &[String]) -> (usize, usize, usize) {
    // Default values
    let mut node_count = 20;
    let mut payment_count = 50;
    let mut malicious_count = 3;

    // Process args if provided
    if args.len() > 1 {
        if let Ok(n) = args[1].parse() {
            node_count = n;
        }
    }

    if args.len() > 2 {
        if let Ok(n) = args[2].parse() {
            payment_count = n;
        }
    }

    if args.len() > 3 {
        if let Ok(n) = args[3].parse() {
            malicious_count = n;

            // Ensure we don't have more malicious nodes than total nodes
            if malicious_count > node_count {
                malicious_count = node_count / 4;
            }
        }
    }

    (node_count, payment_count, malicious_count)
}

// Display usage information
fn print_usage() {
    println!("THELMA: Timelock Heuristic Evaluation for Lightning Movement Analysis");
    println!();
    println!("Usage:");
    println!("  thelma [nodes] [payments] [malicious]");
    println!();
    println!("Arguments:");
    println!("  nodes       - Number of nodes in the network (default: 20)");
    println!("  payments    - Number of payments to simulate (default: 50)");
    println!("  malicious   - Number of malicious nodes (default: 3)");
    println!();
    println!("Example:");
    println!("  thelma 50 100 5   # 50 nodes, 100 payments, 5 malicious nodes");
}
