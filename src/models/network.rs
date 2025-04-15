use std::collections::{HashMap, HashSet};

// Represent a Lightning Network Node
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    pub pub_key: String,
    pub alias: String,
    pub cltv_expiry_delta: u32,
}

impl Node {
    pub fn new(pub_key: &str, alias: &str, cltv_expiry_delta: u32) -> Self {
        Node {
            pub_key: pub_key.to_string(),
            alias: alias.to_string(),
            cltv_expiry_delta,
        }
    }
}

// Represent a channel between two nodes
#[derive(Debug, Clone)]
pub struct Channel {
    pub channel_id: String,
    pub node1: String,
    pub node2: String,
    pub capacity: u64,
}

impl Channel {
    pub fn new(channel_id: &str, node1: &str, node2: &str, capacity: u64) -> Self {
        Channel {
            channel_id: channel_id.to_string(),
            node1: node1.to_string(),
            node2: node2.to_string(),
            capacity,
        }
    }
}

// Core data structure for tracking Lightning Network state
pub struct LightningNetworkMap {
    pub nodes: HashMap<String, Node>,
    pub channels: Vec<Channel>,
    pub adjacency_list: HashMap<String, Vec<String>>,
    pub current_block_height: u32,
}

impl LightningNetworkMap {
    pub fn new(current_block_height: u32) -> Self {
        LightningNetworkMap {
            nodes: HashMap::new(),
            channels: Vec::new(),
            adjacency_list: HashMap::new(),
            current_block_height,
        }
    }

    pub fn add_node(&mut self, node: Node) {
        self.adjacency_list.entry(node.pub_key.clone()).or_insert(Vec::new());
        self.nodes.insert(node.pub_key.clone(), node);
    }

    pub fn add_channel(&mut self, channel: Channel) {
        // Update adjacency list
        self.adjacency_list.entry(channel.node1.clone())
            .or_insert(Vec::new())
            .push(channel.node2.clone());

        self.adjacency_list.entry(channel.node2.clone())
            .or_insert(Vec::new())
            .push(channel.node1.clone());

        self.channels.push(channel);
    }

    // Get all neighbors of a node
    pub fn get_neighbors(&self, node_pub_key: &str) -> Option<&Vec<String>> {
        self.adjacency_list.get(node_pub_key)
    }

    // Find possible routes from a node given a remaining CLTV budget
    pub fn find_possible_routes_with_budget(&self,
                                            starting_node: &str,
                                            cltv_budget: u32,
                                            max_hops: usize) -> Vec<Vec<String>> {
        let mut routes = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = vec![starting_node.to_string()];

        self.dfs_routes(&mut routes, &mut visited, &mut current_path, starting_node, cltv_budget, 0, max_hops);

        routes
    }

    // DFS helper for route finding
    fn dfs_routes(&self,
                  routes: &mut Vec<Vec<String>>,
                  visited: &mut HashSet<String>,
                  current_path: &mut Vec<String>,
                  current_node: &str,
                  budget: u32,
                  used_budget: u32,
                  max_depth: usize) {
        if current_path.len() > max_depth || used_budget > budget {
            return;
        }

        visited.insert(current_node.to_string());

        // If we've used a plausible amount of the budget, this could be a destination
        // For simplicity, we're using a constant DEFAULT_FINAL_CLTV_DELTA assumption
        // In a real implementation, this would consider the node's actual preferences
        const DEFAULT_FINAL_CLTV_DELTA: u32 = 40;

        if current_path.len() > 1 && used_budget <= budget &&
            used_budget >= budget - DEFAULT_FINAL_CLTV_DELTA {
            routes.push(current_path.clone());
        }

        if let Some(neighbors) = self.get_neighbors(current_node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    // Get CLTV delta for the next hop
                    let next_hop_delta = match self.nodes.get(neighbor) {
                        Some(node) => node.cltv_expiry_delta,
                        None => 14, // Minimum per-hop CLTV delta if unknown
                    };

                    current_path.push(neighbor.clone());
                    self.dfs_routes(routes, visited, current_path, neighbor,
                                    budget, used_budget + next_hop_delta, max_depth);
                    current_path.pop();
                }
            }
        }

        visited.remove(current_node);
    }

    #[cfg(test)]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(test)]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_node() {
        let mut network = LightningNetworkMap::new(700000);
        let node = Node::new("test_key", "Test Node", 40);
        network.add_node(node);

        assert_eq!(network.node_count(), 1);
        assert!(network.nodes.contains_key("test_key"));
    }

    #[test]
    fn test_add_channel() {
        let mut network = LightningNetworkMap::new(700000);
        let node1 = Node::new("key1", "Node 1", 40);
        let node2 = Node::new("key2", "Node 2", 40);

        network.add_node(node1);
        network.add_node(node2);

        network.add_channel(Channel::new("chan1", "key1", "key2", 1000000));

        assert_eq!(network.channel_count(), 1);
        assert!(network.adjacency_list["key1"].contains(&"key2".to_string()));
        assert!(network.adjacency_list["key2"].contains(&"key1".to_string()));
    }

    #[test]
    fn test_find_routes() {
        let mut network = LightningNetworkMap::new(700000);

        // Add nodes in a simple path
        let nodes = vec![
            Node::new("node1", "Node 1", 20),
            Node::new("node2", "Node 2", 20),
            Node::new("node3", "Node 3", 20),
            Node::new("node4", "Node 4", 20),
        ];

        for node in nodes {
            network.add_node(node);
        }

        // Connect in a line
        network.add_channel(Channel::new("chan1", "node1", "node2", 1000000));
        network.add_channel(Channel::new("chan2", "node2", "node3", 1000000));
        network.add_channel(Channel::new("chan3", "node3", "node4", 1000000));

        // Budget for exactly 2 hops (node1 -> node2 -> node3)
        let routes = network.find_possible_routes_with_budget("node1", 40, 3);
        assert!(routes.contains(&vec!["node1".to_string(), "node2".to_string(), "node3".to_string()]));

        // Budget for all 3 hops
        let routes = network.find_possible_routes_with_budget("node1", 60, 3);
        assert!(routes.contains(&vec!["node1".to_string(), "node2".to_string(), "node3".to_string(), "node4".to_string()]));
    }
}
