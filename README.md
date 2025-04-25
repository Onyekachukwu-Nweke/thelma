# THELMA: Timelock Heuristic Evaluation for Lightning Movement Analysis

THELMA is a research tool that demonstrates how malicious nodes in the Lightning Network could potentially deanonymize payment routes by analyzing HTLC timelock values. It simulates a scenario where multiple colluding nodes in the network observe payment HTLCs and attempt to correlate them based on timelock information.

## Background

Lightning Network payments use onion routing for privacy, but certain observable information may still enable route deanonymization by adversarial nodes:

1. **Payment Hash**: Identical across the entire route (this will be fixed by PTLCs in the future)
2. **CLTV Timelock Values**: Decreasing along the payment path in predictable ways

## How THELMA Works

### Timelock Analysis Attack

When a node receives an HTLC, the CLTV expiry is determined by:
- Current block height
- Final CLTV delta (set by receiving node)
- Random offset (added for privacy)
- Sum of CLTV deltas of all downstream nodes

A malicious node can:
1. Observe the CLTV expiry on incoming HTLCs
2. Calculate "timelock budget" by subtracting current block height
3. Estimate the remaining hops based on common CLTV delta values
4. Narrow down potential recipients by analyzing the network topology

### The THELMA Simulator

This program demonstrates the attack by:

1. Creating a simulated Lightning Network with nodes and channels
2. Designating some nodes as "malicious" (colluding attackers)
3. Simulating payment forwarding through the network
4. Recording HTLC observations at malicious nodes
5. Analyzing timelock values to determine potential recipients
6. Correlating observations from multiple malicious nodes
7. Generating reports on potential payment endpoints

## Building and Running

```bash
# Build the project
cargo build --release

# Run with default settings (20 nodes, 50 payments, 3 malicious nodes)
cargo run --release

# Run with custom parameters
cargo run --release -- 50 100 5
```

### Command-line Arguments

```
thelma [nodes] [payments] [malicious]

Arguments:
  nodes       - Number of nodes in the network (default: 20)
  payments    - Number of payments to simulate (default: 50)
  malicious   - Number of malicious nodes (default: 3)
```

## Output

THELMA generates two output files:
- `thelma_report.md` - Human-readable report
- `thelma_report.json` - Machine-readable JSON data

## Project Structure

```
thelma/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                 # Entry point, setup and simulation runner
    ├── models/                 # Core data structures
    │   ├── mod.rs              # Module exports
    │   ├── network.rs          # Lightning network model (nodes, channels)
    │   └── htlc.rs             # HTLC observation data structures
    ├── surveillance/           # Surveillance logic
    │   ├── mod.rs              # Module exports
    │   ├── operation.rs        # Core surveillance operation
    │   ├── analyzer.rs         # HTLC analysis algorithms 
    │   └── reporter.rs         # Report generation
    └── simulation/             # Network simulation components
        ├── mod.rs              # Module exports
        ├── network_generator.rs # Test network creation
        ├── payment_simulator.rs # Payment routing simulation
        └── utils.rs            # Helper functions
```

## Privacy Implications & Mitigations

This simulation highlights why additional privacy measures are important in Lightning Network:

- **PTLC (Point Time Locked Contracts)**: Will replace HTLCs and payment hashes with unique values per hop
- **Variable CLTV deltas**: Using non-standard CLTV deltas can make route analysis harder
- **Random route selection**: Not always choosing the cheapest/shortest route
- **Random CLTV padding**: Adding variable padding to final CLTV values (already implemented)

## Disclaimer

This code is for educational and research purposes only. It demonstrates a known privacy consideration in the Lightning Network protocol.