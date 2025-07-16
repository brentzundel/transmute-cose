# CCF Receipt Verification Implementation

This module implements the CCF (Confidential Consortium Framework) receipt verification functionality based on the IETF draft [draft-birkholz-cose-receipts-ccf-profile](https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/).

## Overview

CCF receipts provide cryptographic proof that a statement has been included in a transparent ledger. This implementation supports:

- **Receipt Structure Verification**: Validates the structure of CCF receipts
- **Inclusion Proof Verification**: Verifies Merkle tree inclusion proofs
- **Certificate-based Verification**: Uses embedded certificates to verify receipt signatures
- **Transparent Statement Verification**: Verifies statements with CCF receipts

## Key Components

### 1. CCF Tree Implementation (`ccf_tree.ts`)

Implements the CCF-specific Merkle tree verification algorithm:

```typescript
import { CCFTree } from './ccf_tree'

// Verify inclusion proof
const verified = CCFTree.verify_inclusion_proof(leaf_hash, proof, root_hash)
```

### 2. Receipt Verification (`verify_receipt.ts`)

Main verification functions for CCF receipts:

```typescript
import { verify_receipt, verify_transparent_statement } from './verify_receipt'

// Verify a CCF receipt
const result = await verify_receipt(receipt_cbor, statement_hash)

// Verify transparent statement with receipt
const result = await verify_transparent_statement(statement_cbor, receipt_cbor)
```

### 3. Inclusion Proof Verification (`verify_inclusion_proof.ts`)

Handles CCF-specific inclusion proof verification:

```typescript
import { verify_inclusion_proof, decode_ccf_receipt } from './verify_inclusion_proof'

// Decode CCF receipt
const receipt = decode_ccf_receipt(receipt_cbor)

// Verify inclusion proof
const verified = verify_inclusion_proof(leaf_hash, proof, root_hash)
```

## Usage Examples

### Basic Receipt Verification

```typescript
import * as ccf from './draft-birkholz-cose-receipts-ccf-profile'

// Verify a CCF receipt
const result = await ccf.verify_receipt(receipt_cbor, statement_hash)
if (result.success) {
    console.log('Receipt verified successfully')
    console.log('Root hash:', result.root_hash)
} else {
    console.log('Verification failed:', result.error)
}
```

### Transparent Statement Verification

```typescript
// Verify transparent statement with CCF receipt
const result = await ccf.verify_transparent_statement(
    statement_cbor,
    receipt_cbor
)
```

### Extract and Verify All Receipts

```typescript
// Extract receipts from signed statement
const receipts = ccf.extract_receipts(signed_statement)

// Verify all receipts
const results = await ccf.verify_all_receipts(signed_statement, statement_hash)
```

## CCF Receipt Structure

CCF receipts follow this structure:

```typescript
interface CCFReceipt {
    signature: Uint8Array        // Receipt signature
    inclusion_proof: CCFInclusionProof  // Merkle tree inclusion proof
    root_hash: Uint8Array       // Merkle tree root hash
    service_id: string          // CCF service identifier
    cert: Uint8Array           // Embedded certificate
}

interface CCFInclusionProof {
    leaf_index: number          // Index of the leaf in the tree
    tree_size: number          // Total size of the tree
    proof: Uint8Array[]        // Merkle tree proof elements
}
```

## Verification Process

The CCF receipt verification process includes:

1. **Structure Validation**: Verify the receipt has the correct format
2. **Certificate Verification**: Extract and validate the embedded certificate
3. **Signature Verification**: Verify the receipt signature using the certificate
4. **Inclusion Proof Verification**: Verify the Merkle tree inclusion proof
5. **Root Hash Validation**: Ensure the reconstructed root matches the claimed root

## Algorithm Details

### CCF Inclusion Proof Algorithm

The CCF inclusion proof verification follows the algorithm described in the IETF draft:

1. **Decompose Proof**: Split the proof into inner and border parts
2. **Chain Inner Elements**: Process inner proof elements based on leaf index
3. **Chain Border Elements**: Process border proof elements
4. **Reconstruct Root**: Combine all elements to reconstruct the Merkle root
5. **Compare Roots**: Verify the reconstructed root matches the claimed root

### Hash Function

CCF uses SHA-256 for all hashing operations:

```typescript
// Hash two children nodes
function hash_children(left: Uint8Array, right: Uint8Array): Uint8Array {
    const hasher = crypto.createHash('sha256')
    hasher.update(left)
    hasher.update(right)
    return hasher.digest()
}
```

## Error Handling

The implementation includes comprehensive error handling:

- **Invalid Receipt Structure**: Validates all required fields
- **Invalid Inclusion Proof**: Checks proof size and leaf index bounds
- **Certificate Errors**: Handles certificate parsing and validation errors
- **Signature Verification Errors**: Handles signature verification failures

## Testing

Run the CCF receipt verification tests:

```bash
npm test -- tests/draft-ietf-scitt-architecture/verify-ccf-receipt.test.ts
```

## Examples

See the comprehensive example in `examples/verify-ccf-receipt.ts` for detailed usage patterns.

## References

- [IETF Draft: COSE Receipts with CCF](https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/)
- [SCITT CCF Ledger Implementation](https://github.com/microsoft/scitt-ccf-ledger)
- [CCF Python Implementation](https://github.com/microsoft/CCF/blob/7e150f4df3cbf8710226cb8da935c14fcaddbe79/python/src/ccf/cose.py#L206)

## Security Considerations

- **Trusted Execution Environment**: CCF networks rely on TEEs for security
- **Certificate Chain Validation**: Always validate the full certificate chain
- **Root Hash Verification**: Ensure the reconstructed root matches the claimed root
- **Service Identity**: Verify the service ID matches expected values

## Limitations

- **Mock Data**: Current implementation uses mock data for demonstration
- **Certificate Validation**: Full certificate chain validation not implemented
- **Signature Verification**: Receipt signature verification is simplified
- **Real Receipts**: Requires actual CCF receipts from a SCITT ledger for full testing 