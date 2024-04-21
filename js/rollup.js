/* eslint-disable no-unused-vars */
const { ContractFactory, ethers } = require("ethers");
const { 
  newMemEmptyTrie, 
  buildEddsa, 
  buildPoseidon, 
  buildBabyjub,
} = require("circomlibjs");
const { randomBytes, createHash } = require("crypto");
const { 
  abi,
  bytecode 
} = require('../out/RollupVerifier.sol/Groth16Verifier.json'); 

const wasm_tester = require("circom_tester").wasm;
const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const { Buffer } = require('node:buffer');

const winston = require('winston');

const logger = winston.createLogger({
  level: 'info', // debug
  format: winston.format.json(),
  defaultMeta: { service: 'zk-rollup' }, // user-service
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

/**
 * buffer to hex
 * @param {any} buff 
 * @returns 
 */
function buf2hex(buff) {
  return BigInt(`0x${BigInt(buff).toString(16)}`);
}

/**
 * number to buffer
 * @param {any} num 
 * @returns 
 */
function num2buf(num) {
  let hex = BigInt(num).toString(16); // DONE: Fix: there was a no radix argument value.
  while (hex.length < 64) {
    hex = '0' + hex;
  }
  return Buffer.from(hex, 'hex');
}

/**
 * A BigInt value, also sometimes just called a BigInt, is a bigint primitive, 
 * created by appending `n` to the end of an integer literal — 10n —, 
 * or by calling the BigInt() function (without the new operator) and giving it an integer value or string value.
 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#description
 */
const FIELD_SIZE = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617")

/**
 * convert siblings to trie elements
 * @param {any[]} siblings 
 * @param {import("circomlibjs").SMT} trie 
 */
function convertSiblings(siblings, trie) {
  let result = [];
  for (let i=0; i<siblings.length; i++) result.push(trie.F.toObject(siblings[i]))
  while (result.length < 10) result.push(0) // membership path is same with merkle tree level
  return result
}


/**
 * @typedef Account
 * @property {any} prvKey
 * @property {any} pubKey
 * @property {any} address
 */

/**
 * @typedef RollupData
 * @property {import("circomlibjs").Eddsa} eddsa
 * @property {import("circomlibjs").Poseidon} poseidon
 * @property {import("circomlibjs").SMT} trie
 * @property {import("circomlibjs").SMT} nonceTrie
 * @property {Account[]} accounts
 * @property {any} contract
 * @property {Record<string, any>} circuits 
 */

/**
 * @typedef TransferRequest 
 * @property {any} ownerPubKey 
 * @property {any} targetAddress 
 * @property {number} nftID 
 * @property {number} nonce
 * @property {any} signature
 */

/**
 * 
 * @param {Account} owner 
 * @param {Account} target 
 * @param {number} nftID 
 * @param {number} nonce 
 * @param {import("circomlibjs").Poseidon} poseidon 
 * @param {import("circomlibjs").Eddsa} eddsa 
 * @returns 
 */
function createTransferRequest(
    owner, 
    target, 
    nftID, 
    nonce,
    poseidon,
    eddsa
  ) {
    const transactionHash = poseidon([
      buf2hex(target.address), 
      nftID, 
      buf2hex(nonce)
    ])

    const signature = eddsa.signPoseidon(owner.prvKey, transactionHash);

    return {
      ownerPubKey: owner.pubKey,
      targetAddress: target.address,
      nftID,
      nonce,
      signature
    }
}

/**
 * 
 * @param {Account} from 
 * @param {Account} to 
 * @param {number} nftID 
 * @param {RollupData} rollupdata
 * @param {any} circuit
 */
async function transferNFT(from, to, nftID, rollupdata, circuit) {
  // get the nonce for the NFT
  const nonce = Number(BigInt(rollupdata.nonceTrie.F.toObject(
      (await rollupdata.nonceTrie.find(nftID)).foundValue
    )));
  
  // create transfer request
  const transferRequest = await createTransferRequest(
    from, to, nftID, nonce,
    rollupdata.poseidon,
    rollupdata.eddsa
  )

  // move the NFT  to the new  owner
  const nft_res = await rollupdata.trie.update(nftID, transferRequest.targetAddress);
  // increate nonce for the NFT
  const nonce_res = await rollupdata.nonceTrie.update(nftID, transferRequest.nonce + 1);

  // generate and check zkp
  let nft_siblings = convertSiblings(nft_res.siblings, rollupdata.trie);
  let nonce_sibligns = convertSiblings(nonce_res.siblings, rollupdata.nonceTrie)

  const inputs = {
    targetAddress: buf2hex(transferRequest.targetAddress),
    nftID: transferRequest.nftID,
    nonce: buf2hex(transferRequest.nonce),
    Ax: rollupdata.eddsa.F.toObject(transferRequest.ownerPubKey[0]),
    Ay: rollupdata.eddsa.F.toObject(transferRequest.ownerPubKey[1]),
    R8x: rollupdata.eddsa.F.toObject(transferRequest.signature.R8[0]),
    R8y: rollupdata.eddsa.F.toObject(transferRequest.signature.R8[1]),
    S: transferRequest.signature.S,
    oldRoot: rollupdata.trie.F.toObject(nft_res.oldRoot),
    siblings: nft_siblings,
    nonceOldRoot: rollupdata.nonceTrie.F.toObject(nonce_res.oldRoot),
    nonceSiblings: nonce_sibligns
  }

  const w = await circuit.calculateWitness(inputs, true);
  await circuit.checkConstraints(w);
  await circuit.assertOut(w, {
    newRoot: rollupdata.trie.F.toObject(nft_res.newRoot),
    nonceNewRoot: rollupdata.nonceTrie.F.toObject(nonce_res.newRoot)
  })

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    // eslint-disable-next-line no-undef
    path.join(__dirname, "../circuits/build", "rollup_tx_js/rollup_tx.wasm"),
    // eslint-disable-next-line no-undef
    path.join(__dirname, "../circuits/build", "rollup_tx.zkey")
  )

  const vkey = JSON.parse(
    fs.readFileSync(
      path.join(
        // eslint-disable-next-line no-undef
        __dirname, 
        "../circuits/build",
        "rollup_tx_vkey.json"
        ),"utf8"))
  const rollup_tx_res = await snarkjs.groth16.verify(vkey, publicSignals, proof)
  console.log(`\nrollup_tx_res: ${rollup_tx_res}`);
}

/**
 * Batch process of transfering NFTs
 * @param {TransferRequest[]} transferRequestList 
 * @param {RollupData} rollupdata
 */
async function batchTransferNFTs(transferRequestList, rollupdata) {
  let targetAddressList = [];
  let nftIDList = [];
  let nonceList = [];
  let AxList = [];
  let AyList = [];
  let SList = [];
  let R8xList = [];
  let R8yList = [];
  let siblingsList = [];
  let nonceSiblingsList = [];

  const oldRoot = rollupdata.trie.F.toObject(rollupdata.trie.root);
  const nonceOldRoot = rollupdata.nonceTrie.F.toObject(rollupdata.nonceTrie.root);

  for (const transferRequest of transferRequestList) {
    
    targetAddressList.push(buf2hex(transferRequest.targetAddress))
    nftIDList.push(buf2hex(transferRequest.nftID))
    nonceList.push(buf2hex(transferRequest.nonce))
    AxList.push(rollupdata.eddsa.F.toObject(transferRequest.ownerPubKey[0]))
    AyList.push(rollupdata.eddsa.F.toObject(transferRequest.ownerPubKey[1]))
    SList.push(transferRequest.signature.S)
    R8xList.push(rollupdata.eddsa.F.toObject(transferRequest.signature.R8[0]))
    R8yList.push(rollupdata.eddsa.F.toObject(transferRequest.signature.R8[1]))

    const res1 = await rollupdata.trie.update(transferRequest.nftID, transferRequest.targetAddress)
    siblingsList.push(convertSiblings(res1.siblings, rollupdata.trie))

    const res2 = await rollupdata.nonceTrie.update(transferRequest.nftID, transferRequest.nonce + 1)
    nonceSiblingsList.push(convertSiblings(res2.siblings, rollupdata.nonceTrie))
  }

  const newRoot = rollupdata.trie.F.toObject(rollupdata.trie.root)
  const nonceNewRoot = rollupdata.nonceTrie.F.toObject(rollupdata.nonceTrie.root)

  let transactionBuffers = [];
  for (const transferRequest of transferRequestList) {
    transactionBuffers.push(num2buf(transferRequest.nftID))
  }
  for (const transferRequest of transferRequestList) {
    transactionBuffers.push(num2buf(transferRequest.targetAddress))
  }

  const hash = createHash("sha256").update(Buffer.concat(transactionBuffers)).digest("hex");
  const ffhash = BigInt(`0x${hash}`) % FIELD_SIZE;
  const transactionListHash = `0x${ffhash.toString(16)}`; // hex

  const oldStateHash = rollupdata.poseidon([oldRoot, nonceOldRoot])
  const newStateHash = rollupdata.poseidon([newRoot, nonceNewRoot])

  const inputs = {
    oldRoot,
    nonceOldRoot,
    newRoot,
    nonceNewRoot,
    nftIDList,
    targetAddressList,
    nonceList,
    AxList,
    AyList,
    SList,
    R8xList,
    R8yList,
    siblingsList,
    nonceSiblingsList,
    transactionListHash,
    oldStateHash: rollupdata.poseidon.F.toObject(oldStateHash),
    newStateHash: rollupdata.poseidon.F.toObject(newStateHash)
  }

  const circuit = getRollupCircuit.apply(rollupdata.circuits)

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs, 
    // eslint-disable-next-line no-undef
    path.join(__dirname, "../circuits/build", "rollup_js/rollup.wasm"),
    // eslint-disable-next-line no-undef
    path.join(__dirname, "../circuits/build", "rollup.zkey") 
  );
  
  const vkey = JSON.parse(
    fs.readFileSync(
      path.join(
        // eslint-disable-next-line no-undef
        __dirname, 
        "../circuits/build",
        "rollup_vkey.json"
        ),"utf8"))
  const rollup_res = await snarkjs.groth16.verify(vkey, publicSignals, proof)
  logger.info(rollup_res);

  console.log(`\nrollup_res: ${rollup_res}`);
  
  const w = await circuit.calculateWitness(inputs, true);
  await circuit.checkConstraints(w);
}

/**
 * 
 * @param {SMT} _trie
 * @param {SMT} _nonceTrie
 * @param {TransferRequest[]} transferRequestList
 * @param {RollupData} rollupdata
 */
async function generateBatchTransferZKP(_trie, _nonceTrie, transferRequestList, rollupdata) {
  let targetAddressList = [];
  let nftIDList = [];
  let nonceList = [];
  let AxList = [];
  let AyList = [];
  let SList = [];
  let R8xList = [];
  let R8yList = [];
  let siblingsList = [];
  let nonceSiblingsList = [];

  const oldRoot = _trie.F.toObject(_trie.root);
  const nonceOldRoot = _nonceTrie.F.toObject(_nonceTrie.root);

  for(const transferRequest of transferRequestList){ 

    targetAddressList.push(buf2hex(transferRequest.targetAddress))
    nftIDList.push(buf2hex(transferRequest.nftID))
    nonceList.push(buf2hex(transferRequest.nonce))
    AxList.push(rollupdata.eddsa.F.toObject(transferRequest.ownerPubKey[0]))
    AyList.push(rollupdata.eddsa.F.toObject(transferRequest.ownerPubKey[1]))
    SList.push(transferRequest.signature.S)
    R8xList.push(rollupdata.eddsa.F.toObject(transferRequest.signature.R8[0]))
    R8yList.push(rollupdata.eddsa.F.toObject(transferRequest.signature.R8[1]))

    const trie_update_res = await _trie.update(transferRequest.nftID, transferRequest.targetAddress)
    siblingsList.push(convertSiblings(trie_update_res.siblings, _trie))
    const noncetrie_update_res = await _nonceTrie.update(transferRequest.nftID, transferRequest.nonce+1)
    nonceSiblingsList.push(convertSiblings(noncetrie_update_res.siblings, _nonceTrie))
  }

  const newRoot = _trie.F.toObject(_trie.root)
  const nonceNewRoot = _nonceTrie.F.toObject(_nonceTrie.root);
  

  let transactionBuffers = [];
  for (const transferRequest of transferRequestList) {
    transactionBuffers.push(num2buf(transferRequest.nftID))
  }
  for (const transferRequest of transferRequestList) {
    transactionBuffers.push(num2buf(transferRequest.targetAddress))
  }
  
  const hash = createHash("sha256").update(Buffer.concat(transactionBuffers)).digest("hex");
  const ffhash = BigInt(`0x${hash}`) % FIELD_SIZE;
  const transactionListHash = `0x${ffhash.toString(16)}`; // hex

  const oldStateHash = rollupdata.poseidon([oldRoot, nonceOldRoot])
  const newStateHash = rollupdata.poseidon([newRoot, nonceNewRoot])

  const inputs = {
    oldRoot,
    nonceOldRoot,
    newRoot,
    nonceNewRoot,
    nftIDList,
    targetAddressList,
    nonceList,
    AxList,
    AyList,
    SList,
    R8xList,
    R8yList,
    siblingsList,
    nonceSiblingsList,
    transactionListHash,
    oldStateHash: rollupdata.poseidon.F.toObject(oldStateHash),
    newStateHash: rollupdata.poseidon.F.toObject(newStateHash)
  }
  
  return await snarkjs.groth16.fullProve(
    inputs, 
    // eslint-disable-next-line no-undef
    path.join(__dirname, "../circuits/build", "rollup_js/rollup.wasm"),
    // eslint-disable-next-line no-undef
    path.join(__dirname, "../circuits/build", "rollup.zkey") 
  );
}

function getRollupCircuit() {
  return this[Symbol.for("rollupCircuit")];
}
function getVerifyRollupTxCircuit() {
  return this[Symbol.for("verifyRollupTxCircuit")];
}
function getVerifyTransferCircuit() {
  return this[Symbol.for("verifyTransferCircuit")];
}

/**
 * Initialize all necessary data
 * @returns {Promise<RollupData>} global object
 */
async function init() {
  let eddsa = await buildEddsa()
  let poseidon = await buildPoseidon()
  let trie = await newMemEmptyTrie()
  let nonceTrie = await newMemEmptyTrie()
  let accounts = []
  let circuits = {};

  // eslint-disable-next-line no-undef
  const verifyTransferCircuit = await wasm_tester(path.join(__dirname, "..", "circuits", "verify_transfer_request_main.circom"))
  circuits[Symbol.for("verifyTransferCircuit")] = verifyTransferCircuit;
  
  // eslint-disable-next-line no-undef
  const verifyRollupTxCircuit = await wasm_tester(path.join(__dirname, "..", "circuits", "rollup_tx_main.circom"));
  circuits[Symbol.for("verifyRollupTxCircuit")] = verifyRollupTxCircuit;

  // eslint-disable-next-line no-undef
  const rollupCircuit = await wasm_tester(path.join(__dirname, "..", "circuits", "rollup.circom"));
  circuits[Symbol.for("rollupCircuit")] = rollupCircuit;

  // If no `url` is provided, it connects to the default
  // http://localhost:8545, which most nodes use.
  const provider = new ethers.JsonRpcProvider()

  // The provider also allows signing transactions
  // to send ether and pay to change state within the blockchain.
  // For this, we need the account signer...
  // Get write access as an account by getting the signer
  const signer = await provider.getSigner()
  const blockNumber = await provider.getBlockNumber() 
  const address = await signer.getAddress();

  const contractFactory = new ContractFactory(
    abi, 
    bytecode.object, 
    signer 
  );
  const contract = await contractFactory.deploy();

  for (let i = 0; i < 5; i++) {
    // generate private and public eddsa keys, 
    // the public address is the poseidon hash of the public key
    const prvKey = randomBytes(32);
    const pubKey = eddsa.prv2pub(prvKey);
    accounts[i] = {
      prvKey: prvKey,
      pubKey: pubKey,
      address: trie.F.toObject(poseidon(pubKey))
    }
  }
  
  for (let i=0; i<=5; i++) {
    // generate 5 NFTs, and set the first account as owner
    await trie.insert(i, accounts[0].address);
    await nonceTrie.insert(i,0);
  }
  
  return {
    eddsa,
    poseidon,
    trie,
    nonceTrie,
    accounts,
    contract,
    circuits
  }
}

module.exports = {
  buf2hex,
  convertSiblings,
  createTransferRequest,
  transferNFT,
  batchTransferNFTs,
  getRollupCircuit,
  getVerifyRollupTxCircuit,
  getVerifyTransferCircuit,
  generateBatchTransferZKP,
  init
}