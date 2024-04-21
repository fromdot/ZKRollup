pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/*
  template instances: 170
  non-linear constraints: 4468
  linear constraints: 0
  public inputs: 0
  private inputs: 8
  public outputs: 0
  wires: 4473
  labels: 22187

  Plonk constraints: 22296
  
  https://github.com/iden3/snarkjs/blob/master/README.md
  [maxConstraints]: 8k	
  [power]: powersOfTau28_hez_final_13.ptau	
  [hash]: 58efc8bf2834d04768a3d7ffcd8e1e23d461561729beaac4e3e7a47829a1c9066d5320241e124a1a8e8aa6c75be0ba66f65bc8239a0542ed38e11276f6fdb4d9
*/

template VerifyTransferRequest() {
  signal input targetAddress;
  signal input nftID;
  signal input nonce;

  signal input Ax;
  signal input Ay;
  signal input S;
  signal input R8x;
  signal input R8y;

  component eddsa = EdDSAPoseidonVerifier();
  component poseidon = Poseidon(3); // input length 3

  // calculate the transaction hash
  poseidon.inputs[0] <== targetAddress;
  poseidon.inputs[1] <== nftID;
  poseidon.inputs[2] <== nonce;

  // verify the signature on the transaction hash
  eddsa.enabled <== 1; // check flag 
  eddsa.Ax <== Ax;
  eddsa.Ay <== Ay;
  eddsa.S <== S;
  eddsa.R8x <== R8x;
  eddsa.R8y <== R8y;
  eddsa.M <== poseidon.out; // hash
}