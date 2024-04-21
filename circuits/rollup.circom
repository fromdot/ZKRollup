pragma circom 2.1.8;

include "rollup_tx.circom";
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/*
  template instances: 356
  non-linear constraints: 409577
  linear constraints: 0
  public inputs: 3
  private inputs: 228 (212 belong to witness)
  public outputs: 0
  wires: 406868
  labels: 2355959

  https://github.com/iden3/snarkjs/blob/master/README.md
  [maxConstraints]: 512k	
  [power]: powersOfTau28_hez_final_19.ptau	
  [hash]: bca9d8b04242f175189872c42ceaa21e2951e0f0f272a0cc54fc37193ff6648600eaf1c555c70cdedfaf9fb74927de7aa1d33dc1e2a7f1a50619484989da0887

  zkey generating time (around 2min)
  2024-03-25T20:58:27+09:00
  2024-03-25T21:00:39+09:00
*/

template Rollup(nLevels, nTransactions) {
  signal input oldRoot;
  signal input nonceOldRoot;

  signal input newRoot;
  signal input nonceNewRoot;

  signal input nftIDList[nTransactions];
  signal input targetAddressList[nTransactions];
  signal input nonceList[nTransactions];

  signal input AxList[nTransactions];
  signal input AyList[nTransactions];
  signal input SList[nTransactions];
  signal input R8xList[nTransactions];
  signal input R8yList[nTransactions];

  signal input siblingsList[nTransactions][nLevels]; // nLevels length of membership path list
  signal input nonceSiblingsList[nTransactions][nLevels];

  signal input transactionListHash;
  signal input oldStateHash;
  signal input newStateHash;

  // verify the transactions in the transaction list, and calculate the new root
  var root = oldRoot;
  var nonceRoot = nonceOldRoot;

  component rollupVerifier[nTransactions]; 

  for (var i = 0; i < nTransactions; i++) {
    rollupVerifier[i] = RollupTransactionVerifier(nLevels);

    rollupVerifier[i].nftID <== nftIDList[i];
    rollupVerifier[i].targetAddress <== targetAddressList[i];
    rollupVerifier[i].nonce <== nonceList[i];
    
    rollupVerifier[i].Ax  <== AxList[i];
    rollupVerifier[i].Ay  <== AyList[i];

    rollupVerifier[i].S   <== SList[i];
    rollupVerifier[i].R8x <== R8xList[i];
    rollupVerifier[i].R8y <== R8yList[i];

    rollupVerifier[i].siblings <== siblingsList[i];
    rollupVerifier[i].oldRoot <== root;

    rollupVerifier[i].nonceSiblings <== nonceSiblingsList[i];
    rollupVerifier[i].nonceOldRoot <== nonceRoot;

    root      = rollupVerifier[i].newRoot;
    nonceRoot = rollupVerifier[i].nonceNewRoot;
  }

  // compute sha256 hash of the transaction list
  component sha = Sha256(nTransactions * 2 * 32 * 8); // 2 * 32 bytes initialize
  component address2bits[nTransactions];
  component nftid2bits[nTransactions];

  // TODO: 나중에 nftid, targetaddress loop 순서 바꿔보기 (javascript도 수정해야함)
  // TODO: sha 계산이 js 와 안맞음. 업데이트 됐는지 다시 확인. endianness 문제인가? 비트순서?
  var c = 0;
  for(var i=0; i<nTransactions; i++) {
    nftid2bits[i] = Num2Bits(32 * 8);
    nftid2bits[i].in <== nftIDList[i];
    for(var j=0; j<32 * 8; j++) {
      sha.in[c] <== nftid2bits[i].out[(32 * 8) - 1 - j];
      c++;
    }
  }
  for(var i=0; i<nTransactions; i++) {
    address2bits[i] = Num2Bits(32 * 8); // 32 bytes initialize
    address2bits[i].in <== targetAddressList[i];
    for(var j=0; j<32 * 8; j++) {
      sha.in[c] <== address2bits[i].out[(32 * 8) - 1 - j]; // from last index to 0 (little endian to big endian?)
      c++;
    }
  }

  component bits2num = Bits2Num(256);
  for(var i=0; i<256; i++) {
    bits2num.in[i] <== sha.out[255 - i]; // big endian to little endian?
  }

  // check the contraints of root hash after updating the trees
  transactionListHash === bits2num.out;
  newRoot === root;
  nonceNewRoot === nonceRoot;

  // check old trees state
  component oldStateHasher = Poseidon(2);
  oldStateHasher.inputs[0] <== oldRoot;
  oldStateHasher.inputs[1] <== nonceOldRoot;

  oldStateHash === oldStateHasher.out;

  // check new trees state (TODO: is it really necessary? to reduce number of parameters? so it use only one compare operation)
  component newStateHasher = Poseidon(2);
  newStateHasher.inputs[0] <== newRoot;
  newStateHasher.inputs[1] <== nonceNewRoot;

  newStateHash === newStateHasher.out;
}

component main {public [transactionListHash, oldStateHash, newStateHash]} = Rollup(10, 8);