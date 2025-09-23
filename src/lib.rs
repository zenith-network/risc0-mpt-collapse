/// Builds an Alloy trie with merkle proof for all nodes
///
/// # Arguments
/// * `items` - Key-value pairs to insert into the trie
///
/// # Returns
/// * Root hash and RLP-encoded proof nodes
pub fn build_alloy_trie_with_proof<K: AsRef<[u8]> + Ord, V: AsRef<[u8]>>(
  items: &[(K, V)],
) -> (alloy_primitives::B256, Vec<alloy_primitives::Bytes>) {
  // Sort items by nibble representation (required by alloy-trie hasher).
  let mut sorted_items = items.iter().collect::<Vec<_>>();
  sorted_items.sort_by_key(|(k, _)| alloy_trie::Nibbles::unpack(k.as_ref()));

  // Collect all key paths for proof generation.
  let proof_key_paths = sorted_items
    .iter()
    .map(|(k, _)| alloy_trie::Nibbles::unpack(k.as_ref()))
    .collect();

  // Create alloy trie hasher, with proof retainer.
  let hb = alloy_trie::HashBuilder::default();
  let proof_retainer = alloy_trie::proof::ProofRetainer::new(proof_key_paths);
  let mut hb = hb.with_proof_retainer(proof_retainer);

  // PInsert all items.
  for (key, val) in sorted_items {
    hb.add_leaf(alloy_trie::Nibbles::unpack(key), val.as_ref());
  }

  // Compute root to finalize internal state and make proof nodes available.
  let root_hash = hb.root();

  // Get RLP from proof nodes.
  let rlp_nodes: Vec<alloy_primitives::Bytes> = hb
    .take_proof_nodes()
    .into_nodes_sorted()
    .into_iter()
    .map(|(_, rlp)| rlp)
    .collect();

  (root_hash, rlp_nodes)
}

#[cfg(test)]
mod tests {
  use risc0_ethereum_trie::Trie;

  /// Validates Risc0 trie implementation against Alloy trie (reference implementation).
  ///
  /// Tests three scenarios:
  /// 1. Build trie without removee key - verify Risc0 matches Alloy hash (baseline)
  /// 2. Build trie with removee key - verify Risc0 matches Alloy hash (extended form)
  /// 3. Dynamically remove the removee key from Risc0 trie and verify it matches baseline
  ///
  /// This ensures Risc0's dynamic removal produces correct results by comparing against
  /// Alloy trie as the reference implementation.
  fn check_trie_consistency_with_removee(
    keys: Vec<(alloy_primitives::B256, Vec<u8>)>,
    removee_key: alloy_primitives::B256,
  ) {
    let mut keys_with_removee = keys.clone();
    keys_with_removee.push((removee_key, b"removee".to_vec()));

    // Build trie without removee key.
    let (alloy_hash_before, rlp_nodes_before) = super::build_alloy_trie_with_proof(&keys);
    println!("Alloy hash before: {:?}", alloy_hash_before);

    let r0_trie_before = Trie::from_rlp(rlp_nodes_before).unwrap();
    let r0_hash_before = r0_trie_before.hash_slow();
    println!("Risc0 root hash before: {:?}", r0_hash_before);
    assert_eq!(alloy_hash_before, r0_hash_before);

    // Build trie with removee key.
    let (alloy_hash_after, rlp_nodes_after) =
      super::build_alloy_trie_with_proof(&keys_with_removee);
    println!("Alloy hash after: {:?}", alloy_hash_after);

    let r0_trie_after = Trie::from_rlp(rlp_nodes_after).unwrap();
    let r0_hash_after = r0_trie_after.hash_slow();
    println!("Risc0 root hash after: {:?}", r0_hash_after);
    assert_eq!(alloy_hash_after, r0_hash_after);

    // Get rid of removee key from the latter Risc0 trie and compare.
    let mut r0_trie_modified = r0_trie_after;
    let is_removed = r0_trie_modified.remove(&removee_key);
    assert_eq!(true, is_removed);
    let r0_hash_modified = r0_trie_modified.hash_slow();
    println!(
      "Risc0 root hash after removee key removal: {:?}",
      r0_hash_modified
    );
    assert_eq!(r0_hash_modified, r0_hash_before);
  }

  /// Helper function to create a B256 from a hex string, automatically right-padding with zeros.
  fn key_from_nibbles(path: &str) -> alloy_primitives::B256 {
    let path_padded: String = format!("{:0<64}", path);
    path_padded.parse().expect("Invalid hex string")
  }

  /// Create test data with cleaner key definitions
  fn create_test_data(key_specs: &[(&str, &str)]) -> Vec<(alloy_primitives::B256, Vec<u8>)> {
    key_specs
      .iter()
      .map(|(key_hex, value)| (key_from_nibbles(key_hex), value.as_bytes().to_vec()))
      .collect()
  }

  #[test]
  fn test_case1_collapse_with_parent_branch_and_child_branch() {
    let keys = create_test_data(&[("ABC1", "1"), ("ABD2", "2"), ("E999", "3")]);
    let removee_key = key_from_nibbles("A0FF");
    check_trie_consistency_with_removee(keys, removee_key);
  }

  #[test]
  fn test_case2_collapse_with_parent_branch_and_child_extension() {
    let keys = create_test_data(&[("AB3C1", "1"), ("AB3D2", "2"), ("E9999", "3")]);
    let removee_key = key_from_nibbles("A0FFF");
    check_trie_consistency_with_removee(keys, removee_key);
  }

  #[test]
  fn test_case3_collapse_with_parent_branch_and_child_leaf() {
    let keys = create_test_data(&[("AB1", "1"), ("E99", "2")]);
    let removee_key = key_from_nibbles("A0F");
    check_trie_consistency_with_removee(keys, removee_key);
  }

  #[test]
  fn test_case4_collapse_with_parent_extension_and_child_branch() {
    let keys = create_test_data(&[("ABC1", "1"), ("ABD2", "2")]);
    let removee_key = key_from_nibbles("A0FF");
    check_trie_consistency_with_removee(keys, removee_key);
  }

  #[test]
  fn test_case5_collapse_with_parent_extension_and_child_extension() {
    let keys = create_test_data(&[("AB3C1", "1"), ("AB3D2", "2")]);
    let removee_key = key_from_nibbles("A0FFF");
    check_trie_consistency_with_removee(keys, removee_key);
  }

  #[test]
  fn test_case6_collapse_with_parent_extension_and_child_leaf() {
    let keys = create_test_data(&[("AB1", "1")]);
    let removee_key = key_from_nibbles("A0F");
    check_trie_consistency_with_removee(keys, removee_key);
  }
}
