pub fn build_alloy_trie_with_proof<K: AsRef<[u8]> + Ord, V: AsRef<[u8]>>(
  items: &Vec<(K, V)>,
) -> (alloy_primitives::B256, Vec<alloy_primitives::Bytes>) {
  // Requirement of alloy-trie: items MUST be sorted by key nibbles.
  let mut sorted_items = items.iter().collect::<Vec<_>>();
  sorted_items.sort_by_key(|(k, _)| alloy_trie::Nibbles::unpack(k.as_ref()));
  //println!("Sorted items: {:?}", sorted_items);

  // Me want to retain proof for all nodes.
  let proof_key_paths = sorted_items
    .iter()
    .map(|(k, _)| alloy_trie::Nibbles::unpack(k.as_ref()))
    .collect();
  //println!("Proof key paths: {:?}", proof_key_paths);

  // Create alloy trie hasher, with proof retainer.
  let hb = alloy_trie::HashBuilder::default();
  let proof_retainer = alloy_trie::proof::ProofRetainer::new(proof_key_paths);
  let mut hb = hb.with_proof_retainer(proof_retainer);

  // Push trie items.
  for (key, val) in sorted_items.iter() {
    //println!("Adding item..");
    hb.add_leaf(alloy_trie::Nibbles::unpack(key), val.as_ref());
  }

  // Compute root to finalize internal state and make proof nodes available.
  let root_hash = hb.root();
  //println!("Alloy-trie root hash: {:?}", alloy_root);

  // Get RLP from proof nodes.
  let rlp_nodes: Vec<alloy_primitives::Bytes> = hb
    .take_proof_nodes()
    .into_nodes_sorted()
    .into_iter()
    .map(|(_, rlp)| rlp)
    .collect();
  //println!("Recovered RLP nodes: {:?}", rlp_nodes);
  //println!("Alloy-trie num nodes: {}", rlp_nodes.len());

  (root_hash, rlp_nodes)
}

#[cfg(test)]
mod tests {
  use alloy_primitives::b256;
  use risc0_ethereum_trie::Trie;

  /// Helper function that checks root hash consistency for a given key set
  /// with and without a dummy key. Ensures compatibility with both Alloy and Risc0 implementations.
  fn check_trie_consistency_with_dummy(
    keys: Vec<(alloy_primitives::B256, Vec<u8>)>,
    dummy_key: alloy_primitives::B256,
  ) {
    let mut keys_with_dummy = keys.clone();
    keys_with_dummy.push((dummy_key, b"dummy".to_vec()));

    // Build trie without dummy key
    let (alloy_hash_before, rlp_nodes_before) = super::build_alloy_trie_with_proof(&keys);
    println!("Alloy hash before: {:?}", alloy_hash_before);

    let r0_trie_before = Trie::from_rlp(rlp_nodes_before).unwrap();
    let r0_hash_before = r0_trie_before.hash_slow();
    println!("Risc0 root hash before: {:?}", r0_hash_before);
    assert_eq!(alloy_hash_before, r0_hash_before);

    // Build trie with dummy key
    let (alloy_hash_after, rlp_nodes_after) = super::build_alloy_trie_with_proof(&keys_with_dummy);
    println!("Alloy hash after: {:?}", alloy_hash_after);

    let r0_trie_after = Trie::from_rlp(rlp_nodes_after).unwrap();
    let r0_hash_after = r0_trie_after.hash_slow();
    println!("Risc0 root hash after: {:?}", r0_hash_after);
    assert_eq!(alloy_hash_after, r0_hash_after);

    // Remove dummy key from Risc0 trie and compare
    let mut r0_trie_modified = r0_trie_after;
    let is_removed = r0_trie_modified.remove(&dummy_key);
    assert_eq!(true, is_removed);
    let r0_hash_modified = r0_trie_modified.hash_slow();
    println!(
      "Risc0 root hash after dummy key removal: {:?}",
      r0_hash_modified
    );
    assert_eq!(r0_hash_modified, r0_hash_before);
  }

  #[test]
  fn test_case1_collapse_with_parent_branch_and_child_branch() {
    let keys = vec![
      (
        b256!("0xABC1000000000000000000000000000000000000000000000000000000000000"),
        b"1".to_vec(),
      ),
      (
        b256!("0xABD2000000000000000000000000000000000000000000000000000000000000"),
        b"2".to_vec(),
      ),
      (
        b256!("0xE999000000000000000000000000000000000000000000000000000000000000"),
        b"3".to_vec(),
      ),
    ];
    let dummy_key = b256!("0xA0FF000000000000000000000000000000000000000000000000000000000000");
    check_trie_consistency_with_dummy(keys, dummy_key);
  }

  #[test]
  fn test_case2_collapse_with_parent_branch_and_child_extension() {
    let keys = vec![
      (
        b256!("0xAB3C100000000000000000000000000000000000000000000000000000000000"),
        b"1".to_vec(),
      ),
      (
        b256!("0xAB3D200000000000000000000000000000000000000000000000000000000000"),
        b"2".to_vec(),
      ),
      (
        b256!("0xE999900000000000000000000000000000000000000000000000000000000000"),
        b"3".to_vec(),
      ),
    ];
    let dummy_key = b256!("0xA0FFF00000000000000000000000000000000000000000000000000000000000");
    check_trie_consistency_with_dummy(keys, dummy_key);
  }

  #[test]
  fn test_case3_collapse_with_parent_branch_and_child_leaf() {
    let keys = vec![
      (
        b256!("0xAB10000000000000000000000000000000000000000000000000000000000000"),
        b"1".to_vec(),
      ),
      (
        b256!("0xE990000000000000000000000000000000000000000000000000000000000000"),
        b"2".to_vec(),
      ),
    ];
    let dummy_key = b256!("0xA0F0000000000000000000000000000000000000000000000000000000000000");
    check_trie_consistency_with_dummy(keys, dummy_key);
  }

  #[test]
  fn test_case4_collapse_with_parent_extension_and_child_branch() {
    let keys = vec![
      (
        b256!("0xABC1000000000000000000000000000000000000000000000000000000000000"),
        b"1".to_vec(),
      ),
      (
        b256!("0xABD2000000000000000000000000000000000000000000000000000000000000"),
        b"2".to_vec(),
      ),
    ];
    let dummy_key = b256!("0xA0FF000000000000000000000000000000000000000000000000000000000000");
    check_trie_consistency_with_dummy(keys, dummy_key);
  }

  #[test]
  fn test_case5_collapse_with_parent_extension_and_child_extension() {
    let keys = vec![
      (
        b256!("0xAB3C100000000000000000000000000000000000000000000000000000000000"),
        b"1".to_vec(),
      ),
      (
        b256!("0xAB3D200000000000000000000000000000000000000000000000000000000000"),
        b"2".to_vec(),
      ),
    ];
    let dummy_key = b256!("0xA0FFF00000000000000000000000000000000000000000000000000000000000");
    check_trie_consistency_with_dummy(keys, dummy_key);
  }

  #[test]
  fn test_case6_collapse_with_parent_extension_and_child_leaf() {
    let keys = vec![(
      b256!("0xAB10000000000000000000000000000000000000000000000000000000000000"),
      b"1".to_vec(),
    )];
    let dummy_key = b256!("0xA0F0000000000000000000000000000000000000000000000000000000000000");
    check_trie_consistency_with_dummy(keys, dummy_key);
  }
}
