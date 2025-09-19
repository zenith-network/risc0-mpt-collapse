use std::borrow::Borrow;

use alloy_trie::proof::ProofRetainer;

fn main() {
  // Define list of items that we want to store in MPT.
  let items: Vec<(&'static str, &'static str)> = vec![
    ("painting", "place"),
    ("guest", "ship"),
    ("mud", "leave"),
    ("paper", "call"),
    ("gate", "boast"),
    ("tongue", "gain"),
    ("baseball", "wait"),
    ("tale", "lie"),
    ("mood", "cope"),
    ("menu", "fear"),
  ];
  println!("Items: {:?}", items);

  // Requirement of alloy-trie: items MUST be sorted by key nibbles.
  let mut sorted_items: Vec<_> = items.into_iter().collect();
  sorted_items.sort_by(|a, b| a.borrow().0.cmp(b.borrow().0.as_ref()));
  //println!("Sorted items: {:?}", sorted_items);

  // Me want to reatin proof for all nodes.
  let proof_keys = sorted_items
    .iter()
    .map(|item| alloy_trie::Nibbles::unpack(item.borrow().0))
    .collect();
  //println!("Proof keys: {:?}", proof_keys);

  // Create alloy trie hasher, with proof reatiner.
  let hb = alloy_trie::HashBuilder::default();
  let proof_retainer = ProofRetainer::new(proof_keys);
  let mut hb = hb.with_proof_retainer(proof_retainer);

  // Add items to MPT.
  for (key, val) in sorted_items.iter() {
    //println!("Adding item..");
    hb.add_leaf(alloy_trie::Nibbles::unpack(key), val.as_ref());
  }

  // Trigger root computation.
  // NOTE: It will allow getting proof nodes.
  let alloy_root = hb.root();
  println!("Alloy-trie root hash: {:?}", alloy_root);

  // Get RLP from proof nodes.
  let rlp_nodes: Vec<alloy_primitives::Bytes> = hb
    .take_proof_nodes()
    .into_nodes_sorted()
    .into_iter()
    .map(|(_, rlp)| rlp)
    .collect();
  //println!("Recovered RLP nodes: {:?}", rlp_nodes);
  println!("Alloy-trie num nodes: {}", rlp_nodes.len());

  // Build risc0 trie from RLP.
  let r0_trie = risc0_ethereum_trie::Trie::from_rlp(rlp_nodes).unwrap();
  let r0_hash = r0_trie.hash_slow();
  println!("Risc0 root hash: {:?}", r0_hash);
  println!("Risc0 num nodes: {}", r0_trie.size());
}
