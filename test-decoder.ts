import * as fs from 'fs'
import { decode_ccf_receipt, verify_ccf_receipt_structure } from './src/drafts/draft-birkholz-cose-receipts-ccf-profile/verify_inclusion_proof'

// Load the actual receipt
const actualReceipt = fs.readFileSync('./tests/draft-ietf-scitt-architecture/actual-receipt.cbor')

console.log('Testing CCF receipt decoder...')
console.log('Receipt size:', actualReceipt.length, 'bytes')

try {
    // Decode the receipt
    const receipt = decode_ccf_receipt(actualReceipt)

    console.log('\nDecoded receipt:')
    console.log('  Service ID:', receipt.service_id)
    console.log('  Leaf Index:', receipt.inclusion_proof.leaf_index)
    console.log('  Tree Size:', receipt.inclusion_proof.tree_size)
    console.log('  Proof Length:', receipt.inclusion_proof.proof.length)
    console.log('  Root Hash Length:', receipt.root_hash.length)
    console.log('  Signature Length:', receipt.signature.length)

    // Verify structure
    const structureValid = verify_ccf_receipt_structure(receipt)
    console.log('\nStructure verification:', structureValid ? '✅ PASS' : '❌ FAIL')

    if (structureValid) {
        console.log('✅ Decoder is working correctly!')
    } else {
        console.log('❌ Decoder has issues')
    }

} catch (error) {
    console.error('❌ Decoder failed:', error)
} 