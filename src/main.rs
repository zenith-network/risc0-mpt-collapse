use std::borrow::Borrow;

use alloy_primitives::{FixedBytes, b256};
use alloy_trie::proof::ProofRetainer;


fn alloy_hash_with_rlp<K: AsRef<[u8]> + Ord, V: AsRef<[u8]>>(
  items: &Vec<(K, V)>,
) -> (alloy_primitives::B256, Vec<alloy_primitives::Bytes>) {
  // Requirement of alloy-trie: items MUST be sorted by key nibbles.
  let mut sorted_items: Vec<(&K, &V)> = items.iter().map(|(k, v)| (k, v)).collect();
  sorted_items.sort_by(|a, b| a.borrow().0.cmp(&b.borrow().0));
  //println!("Sorted items: {:?}", sorted_items);

  // Me want to reatin proof for all nodes.
  let proof_key_paths = sorted_items
    .iter()
    .map(|item| alloy_trie::Nibbles::unpack(item.borrow().0))
    .collect();
  //println!("Proof key paths: {:?}", proof_key_paths);

  // Create alloy trie hasher, with proof reatiner.
  let hb = alloy_trie::HashBuilder::default();
  let proof_retainer = ProofRetainer::new(proof_key_paths);
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

fn main() {
  // Define list of items that we want to store in MPT.
  // In storage tries all keys are exactly 32 bytes long.
  let items: Vec<(FixedBytes<32>, Vec<u8>)> = vec![
    (
      b256!("0xDAB0000000000000000000000000000000000000000000000000000000000000"),
      b"place".to_vec(),
    ),
    (
      b256!("0xDAC0000000000000000000000000000000000000000000000000000000000000"),
      b"ship".to_vec(),
    ),
    (
      b256!("0xEAB0000000000000000000000000000000000000000000000000000000000000"),
      b"leave".to_vec(),
    ),
    (
      b256!("0xEAC0000000000000000000000000000000000000000000000000000000000000"),
      b"call".to_vec(),
    ),
  ];
  //println!("Items: {:?}", items);

  let (alloy_hash, rlp_nodes) = alloy_hash_with_rlp(&items);
  println!("Alloy hash: {:?}", alloy_hash);

  // Build risc0 trie from RLP.
  let r0_trie = risc0_ethereum_trie::Trie::from_rlp(rlp_nodes).unwrap();
  let r0_hash = r0_trie.hash_slow();
  println!("Risc0 root hash: {:?}", r0_hash);
  println!("Risc0 num nodes: {}", r0_trie.size());
}
