# [WIP] ZK Rollup Implementation with snarkjs and circom

# Caution ⚠
This test is not production ready.
Please check this [document](https://github.com/iden3/snarkjs), so that make a safe zkey with contribution process.

# Run test
```
npm run test
```

# Step 

1. Make a verification circuit with circom languge  
: Proof generation
2. Make a smart contract to store transactions and generate verification contract from snarkjs  
: On-chain validation
3. Connect above two with RPC  
: Off-chain intercommunication
