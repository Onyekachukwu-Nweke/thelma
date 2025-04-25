// Utility functions for Lightning Network simulation

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::error::Error;
use rand::Rng;

use crate::models::LightningNetworkMap;

// Generate a random path between two nodes
pub fn generate_random_path(network_map: Arc<Mutex<LightningNetworkMap>>,
                            start: &str,
                            end: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let network = network_map.lock().unwrap();

    // Simple BFS to find a path
    let mut queue = Vec::new();
    let mut visited = HashSet::new();
    let mut pred = HashMap::new();

    visited.insert(start.to_string());
    queue.push(start.to_string());

    while !queue.is_empty() {
        let current = queue.remove(0);

        if current == end {
            break;
        }

        if let Some(neighbors) = network.get_neighbors(&current) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    visited.insert(neighbor.clone());
                    pred.insert(neighbor.clone(), current.clone());
                    queue.push(neighbor.clone());
                }
            }
        }
    }

    // Reconstruct the path
    let mut path = Vec::new();
    let mut current = end.to_string();

    if !pred.contains_key(&current) {
        // No path found
        return Ok(vec![]);
    }

    path.push(current.clone());

    while current != start.to_string() {
        current = pred[&current].clone();
        path.push(current.clone());
    }

    path.reverse();
    Ok(path)
}

// Generate a random path with some randomization (not always shortest path)
pub fn generate_randomized_path(network_map: Arc<Mutex<LightningNetworkMap>>,
                                start: &str,
                                end: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut rng = rand::rng();

    // If we get lucky (20% chance), just find a direct path
    if rng.random_bool(0.2) {
        return generate_random_path(network_map, start, end);
    }

    // Otherwise, route through 1-2 random intermediate nodes
    let network = network_map.lock().unwrap();
    let all_nodes: Vec<String> = network.nodes.keys().cloned().collect();
    drop(network);

    if all_nodes.len() < 3 {
        // Not enough nodes, fall back to direct path
        return generate_random_path(network_map, start, end);
    }

    // Pick 1 or 2 random intermediate nodes
    let num_intermediates = if rng.random_bool(0.5) { 1 } else { 2 };
    let mut intermediate_nodes = Vec::new();

    for _ in 0..num_intermediates {
        let random_idx = rng.random_range(0..all_nodes.len());
        let random_node = &all_nodes[random_idx];

        // Avoid picking start or end or already selected intermediate
        if random_node != start && random_node != end && !intermediate_nodes.contains(random_node) {
            intermediate_nodes.push(random_node.clone());
        }
    }

    // Find path segments and join them
    let mut complete_path = Vec::new();

    if intermediate_nodes.is_empty() {
        // No valid intermediates found, fall back to direct path
        return generate_random_path(network_map, start, end);
    }

    // First segment: start to first intermediate
    let mut current = start;

    for intermediate in &intermediate_nodes {
        let segment = generate_random_path(network_map.clone(), current, intermediate)?;

        if segment.is_empty() {
            // Couldn't find this segment, try direct path instead
            return generate_random_path(network_map, start, end);
        }

        if !complete_path.is_empty() {
            // Avoid duplicating the starting node of each segment
            complete_path.extend_from_slice(&segment[1..]);
        } else {
            complete_path.extend_from_slice(&segment);
        }

        current = intermediate;
    }

    // Final segment: last intermediate to end
    let final_segment = generate_random_path(network_map.clone(), current, end)?;

    if final_segment.is_empty() {
        // Couldn't find final segment, try direct path
        return generate_random_path(network_map, start, end);
    }

    // Add the final segment (skip the first node to avoid duplication)
    complete_path.extend_from_slice(&final_segment[1..]);

    Ok(complete_path)
}

// Find all possible paths between two nodes up to a maximum hop count
pub fn find_all_paths(network_map: Arc<Mutex<LightningNetworkMap>>,
                      start: &str,
                      end: &str,
                      max_hops: usize) -> Vec<Vec<String>> {
    let network = network_map.lock().unwrap();

    let mut all_paths = Vec::new();
    let mut current_path = vec![start.to_string()];
    let mut visited = HashSet::new();

    visited.insert(start.to_string());

    // Use DFS to find all paths
    find_paths_dfs(&network, &mut all_paths, &mut current_path, &mut visited, start, end, max_hops);

    all_paths
}

// Helper function for DFS path finding
fn find_paths_dfs(network: &LightningNetworkMap,
                  all_paths: &mut Vec<Vec<String>>,
                  current_path: &mut Vec<String>,
                  visited: &mut HashSet<String>,
                  current: &str,
                  end: &str,
                  max_hops: usize) {
    // If we've reached the destination, add the path
    if current == end {
        all_paths.push(current_path.clone());
        return;
    }

    // If we've exceeded max hop count, stop this branch
    if current_path.len() > max_hops + 1 {
        return;
    }

    // Try all possible next hops
    if let Some(neighbors) = network.get_neighbors(current) {
        for neighbor in neighbors {
            if !visited.contains(neighbor) {
                // Mark as visited
                visited.insert(neighbor.clone());
                current_path.push(neighbor.clone());

                // Recurse
                find_paths_dfs(network, all_paths, current_path, visited, neighbor, end, max_hops);

                // Backtrack
                current_path.pop();
                visited.remove(neighbor);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Node, Channel};

    #[test]
    fn test_path_finding() {
        // Create a test network
        let network_map = Arc::new(Mutex::new(LightningNetworkMap::new(700000)));

        {
            let mut network = network_map.lock().unwrap();

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

            // Add a shortcut
            network.add_channel(Channel::new("chan4", "node1", "node4", 1000000));
        }

        // Test basic path finding
        let path = generate_random_path(network_map.clone(), "node1", "node4").unwrap();
        assert!(!path.is_empty());
        assert_eq!(path[0], "node1");
        assert_eq!(path[path.len()-1], "node4");

        // Test finding all paths
        let all_paths = find_all_paths(network_map.clone(), "node1", "node4", 3);
        assert_eq!(all_paths.len(), 2); // There should be 2 paths: direct and through nodes 2-3
    }
}