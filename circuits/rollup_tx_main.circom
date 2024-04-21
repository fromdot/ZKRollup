pragma circom 2.1.8;

include "verify_transfer_request.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/*
  template instances: 254
  non-linear constraints: 16678
  linear constraints: 0
  public inputs: 0
  private inputs: 30 (28 belong to witness)
  public outputs: 2
  wires: 16695
  labels: 63932
  Plonk constraints: 133324

  https://github.com/iden3/snarkjs/blob/master/README.md
  [maxConstraints]: 32k	
  [power]: powersOfTau28_hez_final_15.ptau	
  [hash]: 982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e
*/

template RollupTransactionVerifier(nLevels) {
  signal input targetAddress;
  signal input nftID;
  signal input nonce;

  signal input Ax;
  signal input Ay;
  signal input S;
  signal input R8x;
  signal input R8y;

  signal input oldRoot;
  signal input siblings[nLevels];

  signal input nonceOldRoot;
  signal input nonceSiblings[nLevels];

  signal output newRoot;
  signal output nonceNewRoot;

  component transferRequestVerifier = VerifyTransferRequest();
  component addressSMT = SMTProcessor(nLevels);
  component nonceSMT = SMTProcessor(nLevels);
  
  component poseidon = Poseidon(2);

  // verify the transfer request
  transferRequestVerifier.targetAddress <== targetAddress;
  transferRequestVerifier.nftID <== nftID;
  transferRequestVerifier.nonce <== nonce;

  // eddsa public key
  transferRequestVerifier.Ax <== Ax;
  transferRequestVerifier.Ay <== Ay;

  // eddsa signature
  transferRequestVerifier.S <== S;
  transferRequestVerifier.R8x <== R8x;
  transferRequestVerifier.R8y <== R8y;

  // verify the SMT update
  // For the same key(NFT ID), we maintain a two different trees with same structure
  /*
    the old value of the NFT ID(key) has to be the poseidon hash of the signers public key (owner address),
    the new value is the target address
  */
  poseidon.inputs[0] <== Ax;
  poseidon.inputs[1] <== Ay;

  // fnc (0,1) == UPDATE 
  addressSMT.fnc[0] <== 0;
  addressSMT.fnc[1] <== 1;
  addressSMT.oldRoot <== oldRoot;
  addressSMT.siblings <== siblings; // membership path node 
  addressSMT.oldKey <== nftID;
  addressSMT.oldValue <== poseidon.out;
  addressSMT.isOld0 <== 0; // previous value is not zero ?
  addressSMT.newKey <== nftID;
  addressSMT.newValue <== targetAddress;

  // verify nonce SMT update, the `newValue` has to be the `oldValue + 1`
  nonceSMT.fnc[0] <== 0;
  nonceSMT.fnc[1] <== 1;
  nonceSMT.oldRoot <== nonceOldRoot;
  nonceSMT.siblings <== nonceSiblings;
  nonceSMT.oldKey <== nftID;
  nonceSMT.oldValue <== nonce;
  nonceSMT.isOld0 <== 0;
  nonceSMT.newKey <== nftID;
  nonceSMT.newValue <== nonce + 1;

  newRoot <== addressSMT.newRoot;
  nonceNewRoot <== nonceSMT.newRoot;
}

component main {public [nftID]} = RollupTransactionVerifier(10);