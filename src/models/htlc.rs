pub const DEFAULT_FINAL_CLTV_DELTA: u32 = 40;  // Common default in LND
pub const CLTV_EXPIRY_DELTA_MIN: u32 = 14;     // Minimum per-hop CLTV delta
pub const CLTV_RANDOM_OFFSET_MIN: u32 = 0;
pub const CLTV_RANDOM_OFFSET_MAX: u32 = 3 * DEFAULT_FINAL_CLTV_DELTA;  // Maximum random padding

// Represent a HTLC forwarded through the network
#[derive(Debug, Clone)]
pub struct HTLC {
    pub payment_hash: String,
    pub cltv_expiry: u32,
    pub amount: u64,
    pub observed_at_block: u32,
    pub observed_by_node: String,
}

impl HTLC {
    pub fn new(payment_hash: &str, cltv_expiry: u32, amount: u64, observed_at_block: u32, observed_by_node: &str) -> Self {
        HTLC {
            payment_hash: payment_hash.to_string(),
            cltv_expiry,
            amount,
            observed_at_block,
            observed_by_node: observed_by_node.to_string(),
        }
    }

    // Calculate the remaining CLTV "budget" for this HTLC
    pub fn remaining_cltv_budget(&self) -> u32 {
        self.cltv_expiry.saturating_sub(self.observed_at_block)
    }

    // Estimate if this could be a payment near its destination
    pub fn is_likely_near_destination(&self) -> bool {
        let remaining_budget = self.remaining_cltv_budget();
        // If the remaining budget is close to typical final delta + potential random offset
        remaining_budget <= DEFAULT_FINAL_CLTV_DELTA + CLTV_RANDOM_OFFSET_MAX
    }

    // Estimate approximate maximum hops remaining on route
    pub fn max_remaining_hops(&self) -> usize {
        let budget = self.remaining_cltv_budget();

        // Estimate using minimum CLTV delta (most hops possible)
        let theoretical_max = (budget.saturating_sub(DEFAULT_FINAL_CLTV_DELTA) / CLTV_EXPIRY_DELTA_MIN) as usize;

        // Cap to a reasonable number for performance
        std::cmp::min(theoretical_max, 5)
    }

    // Detailed timelock analysis info
    pub fn timelock_analysis(&self) -> TimelockAnalysis {
        let remaining_budget = self.remaining_cltv_budget();
        let final_delta_estimate = remaining_budget.saturating_sub(DEFAULT_FINAL_CLTV_DELTA);
        let could_be_final = final_delta_estimate <= CLTV_RANDOM_OFFSET_MAX;
        let max_hops = self.max_remaining_hops();

        TimelockAnalysis {
            remaining_cltv_budget: remaining_budget,
            estimated_final_delta: final_delta_estimate,
            could_be_final_hop: could_be_final,
            max_remaining_hops: max_hops,
        }
    }
}

// Struct for timelock analysis results
#[derive(Debug, Clone)]
pub struct TimelockAnalysis {
    pub remaining_cltv_budget: u32,
    pub estimated_final_delta: u32,
    pub could_be_final_hop: bool,
    pub max_remaining_hops: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remaining_budget_calculation() {
        let htlc = HTLC::new(
            "test_hash",
            700100,  // expiry
            100000,  // amount
            700000,  // current block
            "test_node"
        );

        assert_eq!(htlc.remaining_cltv_budget(), 100);
    }

    #[test]
    fn test_final_hop_detection() {
        // A payment that might be near its destination
        let final_htlc = HTLC::new(
            "test_hash",
            700040,  // expiry = current + default final delta
            100000,
            700000,
            "test_node"
        );

        assert!(final_htlc.is_likely_near_destination());

        // A payment with many hops remaining
        let mid_route_htlc = HTLC::new(
            "test_hash",
            700200,  // expiry = much higher than final delta
            100000,
            700000,
            "test_node"
        );

        assert!(!mid_route_htlc.is_likely_near_destination());
    }

    #[test]
    fn test_max_hops_estimation() {
        // Minimal remaining budget (at final hop)
        let final_htlc = HTLC::new("hash", 700040, 100000, 700000, "node");
        assert_eq!(final_htlc.max_remaining_hops(), 0);

        // Budget for exactly one more hop
        let one_hop_htlc = HTLC::new("hash", 700054, 100000, 700000, "node");
        assert_eq!(one_hop_htlc.max_remaining_hops(), 1);

        // Budget for many hops
        let multi_hop_htlc = HTLC::new("hash", 700200, 100000, 700000, "node");
        assert!(multi_hop_htlc.max_remaining_hops() > 1);
    }
}