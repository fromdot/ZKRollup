// eslint-disable-next-line no-unused-vars
const {
  test,
  before, 
  describe,
} = require('node:test');
// const assert = require('assert');
const assert = require('node:assert').strict;
const { 
  newMemEmptyTrie, 
} = require("circomlibjs");
const snarkjs = require('snarkjs');
const path = require("node:path");
const fs = require("fs");

const { ContractFactory, ethers } = require("ethers");
const { 
  abi: rollup_abi,
  bytecode: rollup_bytecode 
} = require('../out/Rollup.sol/Rollup.json'); 
const { 
  abi: mytoken_abi,
  bytecode: mytoken_bytecode 
} = require('../out/MyToken.sol/MyToken.json'); 

const { 
  init, 
  buf2hex, 
  createTransferRequest,
  batchTransferNFTs,
  getRollupCircuit,
  getVerifyRollupTxCircuit,
  getVerifyTransferCircuit,
  transferNFT,
  generateBatchTransferZKP
} = require('./rollup');

const winston = require('winston');

// eslint-disable-next-line no-unused-vars
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'user-service' },
  transports: [
    //
    // - Write all logs with importance level of `error` or less to `error.log`
    // - Write all logs with importance level of `info` or less to `combined.log`
    //
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});


describe("# ZK-Rollup for transfering NFT ", () => {
  /** @type {import("./rollup").RollupData} */
  let rollupdata;
  let rollup_contract_address;

  before(async () => {
    rollupdata = await init();
  })
  
  test("##1 Transfer verifier circuit", async () => {
    const req = await createTransferRequest(
      rollupdata.accounts[0],
      rollupdata.accounts[1],
      1,
      0,
      rollupdata.poseidon,
      rollupdata.eddsa
    )

    const inputs = {
      targetAddress: buf2hex(req.targetAddress),
      nftID: req.nftID,
      nonce: buf2hex(req.nonce),
      Ax: rollupdata.eddsa.F.toObject(req.ownerPubKey[0]),
      Ay: rollupdata.eddsa.F.toObject(req.ownerPubKey[1]),
      R8x: rollupdata.eddsa.F.toObject(req.signature.R8[0]),
      R8y: rollupdata.eddsa.F.toObject(req.signature.R8[1]),
      S: req.signature.S
    }

    const circuit = getVerifyTransferCircuit.apply(rollupdata.circuits);
    const w = await circuit.calculateWitness(inputs, true);
    // eslint-disable-next-line no-unused-vars
    const check = await circuit.checkConstraints(w);
    // console.log(`\nw: ${w}`);
    // console.log(`\ncheck: ${check}`);

    const {proof, publicSignals} = await snarkjs.groth16.fullProve(
      inputs,
      // eslint-disable-next-line no-undef
      path.join(__dirname, "../circuits/build", "verify_transfer_request_js/verify_transfer_request.wasm"),
      // eslint-disable-next-line no-undef
      path.join(__dirname, "../circuits/build", "verify_transfer_request.zkey")
    );

    // console.log(`\nproof: ${JSON.stringify(proof,null,2)}`);
    // console.log(`\npublicSignals: ${JSON.stringify(publicSignals,null,2)}`);

    const vkey = JSON.parse(
      fs.readFileSync(
        path.join(
          // eslint-disable-next-line no-undef
          __dirname, 
          "../circuits/build",
          "verify_transfer_request_vkey.json"
          ),"utf8"));
    const verify_transfer_request_res = await snarkjs.groth16.verify(vkey, publicSignals, proof); // at least one needs to be public
    // assert(verify_transfer_request_res);
    console.log(`\nverify_transfer_request_res: ${verify_transfer_request_res}`);
  })

  test("##2 Transfer `NFT 1` from `account 0` to `1`, `1` to `2`", async () => {
    const circuit = getVerifyRollupTxCircuit.apply(rollupdata.circuits);
    await transferNFT(rollupdata.accounts[0], rollupdata.accounts[1], 1, rollupdata, circuit);
    await transferNFT(rollupdata.accounts[1], rollupdata.accounts[2], 1, rollupdata, circuit);
  })
  
  // TODO: Why does this test not worked properly with below test 3-2?
  // test("##3-1 Test the rollup!", async () => {
  //   const req1 =  createTransferRequest(rollupdata.accounts[0], rollupdata.accounts[1], 2, 0, rollupdata.poseidon,rollupdata.eddsa)
  //   const req2 =  createTransferRequest(rollupdata.accounts[1], rollupdata.accounts[2], 2, 1, rollupdata.poseidon,rollupdata.eddsa)
  //   const req3 =  createTransferRequest(rollupdata.accounts[2], rollupdata.accounts[1], 2, 2, rollupdata.poseidon,rollupdata.eddsa)
  //   const req4 =  createTransferRequest(rollupdata.accounts[1], rollupdata.accounts[0], 2, 3, rollupdata.poseidon,rollupdata.eddsa)
  //   const req5 =  createTransferRequest(rollupdata.accounts[0], rollupdata.accounts[1], 2, 4, rollupdata.poseidon,rollupdata.eddsa)
  //   const req6 =  createTransferRequest(rollupdata.accounts[1], rollupdata.accounts[2], 2, 5, rollupdata.poseidon,rollupdata.eddsa)
  //   const req7 =  createTransferRequest(rollupdata.accounts[2], rollupdata.accounts[1], 2, 6, rollupdata.poseidon,rollupdata.eddsa)
  //   const req8 =  createTransferRequest(rollupdata.accounts[1], rollupdata.accounts[0], 2, 7, rollupdata.poseidon,rollupdata.eddsa)

  //   await batchTransferNFTs([
  //     req1,req2,req3,req4,req5,req6,req7,req8
  //   ], rollupdata)
  // })

  const BATCH_SIZE = 8;

  test("##3-2 Test the zk-rollup smart contract", async () => {
    let transferReqs = [];
    let _trie = await newMemEmptyTrie()
    let _nonceTrie = await newMemEmptyTrie()

    // initialize
    for(let i = 1; i<=BATCH_SIZE; i++){
      await _trie.insert(i, rollupdata.accounts[0].address)
      await _nonceTrie.insert(i, 0)
      transferReqs.push(
        createTransferRequest(
          rollupdata.accounts[0],
          rollupdata.accounts[1], i, 0, 
          rollupdata.poseidon, rollupdata.eddsa
      ))
    }
    const oldRoot = _trie.F.toObject(_trie.root)
    const nonceOldRoot = _nonceTrie.F.toObject(_nonceTrie.root)
    const oldStateHash = rollupdata.poseidon.F.toObject(rollupdata.poseidon([oldRoot, nonceOldRoot]))
    
    const provider = new ethers.JsonRpcProvider()
    const signer = await provider.getSigner()
    const RollupContractFactory = new ContractFactory(
      rollup_abi, 
      rollup_bytecode.object, 
      signer 
    );
    const RollupContract = await RollupContractFactory.deploy(oldStateHash, await rollupdata.contract.getAddress());
    rollup_contract_address = await RollupContract.getAddress();

    console.log(rollup_contract_address);
    console.log(RollupContract.address);

    const test = await generateBatchTransferZKP(_trie, _nonceTrie, transferReqs, rollupdata)
    
    const {proof,publicSignals} = test;
    const newRoot = _trie.F.toObject(_trie.root)
    const nonceNewRoot = _nonceTrie.F.toObject(_nonceTrie.root)
    const newStateHash = rollupdata.poseidon.F.toObject(rollupdata.poseidon([newRoot, nonceNewRoot]))

    let tList = [];
    for(const tReq of transferReqs){
      tList.push(BigInt(tReq.nftID))
    }
    for(const tReq of transferReqs){
      tList.push(tReq.targetAddress)
    }

    // console.log(`\npublicSignals[0]: ${publicSignals[0]}`);
    // console.log(`\npublicSignals[0]: ${publicSignals[1]}`);
    // console.log(`\npublicSignals[0]: ${publicSignals[2]}`);
    // console.log(`\npublicSignals[0]: ${publicSignals[3]}`);

    await RollupContract.updateState(
      [proof.pi_a[0],proof.pi_a[1]],
      [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]], // why?
      [proof.pi_c[0], proof.pi_c[1]],
      tList,
      publicSignals[1], publicSignals[2] // oldStateHash, newStateHash
    )

    console.log("--------Hash values are equal?---------");
    console.log(await RollupContract.getStateHash());
    console.log(newStateHash);
    
    // assert.equal(await RollupContract.getStateHash(), newStateHash)
  })
  
  test("##4 Calculate simple NFT transfer gas cost", async () => {
    const provider = new ethers.JsonRpcProvider()
    const signers = await provider.listAccounts()
    const account0 = signers[0]
    const account1 = signers[1]
    const TokenContractFactory = new ContractFactory(
      mytoken_abi, 
      mytoken_bytecode.object, 
      account0 
    );
    const TokenContract = await TokenContractFactory.deploy(account0);
    console.log(`\nTokenContract.interface.fragments: ${JSON.stringify(TokenContract.interface.fragments,null,2)}`);

    console.log(account0);

    for(let i=1; i<=BATCH_SIZE; i++){
      await TokenContract.safeMint(account0.address, i)
    }
    for(let i=1; i<=BATCH_SIZE; i++){
      await TokenContract.safeTransferFrom(account0.address, account1.address, i) // address,address,uint256
    }
  })

  test("##5 Rebuild trie from calldata", async () => {
    let _trie = await newMemEmptyTrie()
    let _nonceTrie = await newMemEmptyTrie()

    // initialize
    for(let i = 1; i<=BATCH_SIZE; i++){
      await _trie.insert(i, rollupdata.accounts[0].address)
      await _nonceTrie.insert(i, 0)
    }

    const provider = new ethers.JsonRpcProvider()
    const signers = await provider.listAccounts()
    const account0 = signers[0]
    const RollupContract = new ethers.Contract( rollup_contract_address , rollup_abi , account0 )
    const events = await RollupContract.queryFilter(RollupContract.filters.StateChanged);
    for(const event of events){
      const tx = await event.provider.getTransaction(event.transactionHash);
      const transferList = RollupContract.interface.parseTransaction(tx).args.at(3);
      for (let i=0; i<BATCH_SIZE; i++) {
        const nftID = transferList[i];
        const address = transferList[BATCH_SIZE + i];
        await _trie.update(nftID, address)
        const nonce = Number(
          BigInt(
            _nonceTrie.F.toObject(
              (await _nonceTrie.find(nftID)).foundValue)
            ))
        await _nonceTrie.update(nftID, nonce + 1)
      }

      const newRoot = _trie.F.toObject(_trie.root)
      const nonceNewRoot = _nonceTrie.F.toObject(_nonceTrie.root)
      const newStateHash = rollupdata.poseidon.F.toObject(rollupdata.poseidon([newRoot, nonceNewRoot]))

      assert.equal(newStateHash, RollupContract.interface.parseTransaction(tx).args.at(5))
    }
  })
})