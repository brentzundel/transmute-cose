import * as fs from 'fs'
import * as cbor from './src/cbor'

// Load the actual receipt
const actualReceipt = fs.readFileSync('./tests/draft-ietf-scitt-architecture/actual-receipt.cbor')

console.log('Analyzing issuer information in receipt...')
console.log('Receipt size:', actualReceipt.length, 'bytes')

// Decode the receipt
const receipt_decoded = cbor.decode(actualReceipt)

// Extract protected header
const protected_header = cbor.decode(receipt_decoded.value[0])
const unprotected_header_receipt = receipt_decoded.value[1]

console.log('\nReceipt protected header keys:', Array.from(protected_header.keys()))

// Look for issuer information in protected header
for (const [key, value] of protected_header.entries()) {
    console.log(`\nKey ${key}:`)
    console.log('  Type:', typeof value)
    console.log('  Value:', value)
}

// Check for CWT claims (key 15)
const claims = protected_header.get(15)
if (claims) {
    console.log('\nCWT Claims found:')
    if (claims instanceof Map) {
        for (const [claim_key, claim_value] of claims.entries()) {
            console.log(`  Claim ${claim_key}:`, claim_value)
        }
    } else {
        console.log('  Claims:', claims)
    }
}

// Check for issuer in unprotected header
console.log('\nReceipt unprotected header keys:', Array.from(unprotected_header_receipt.keys()))

// Look for any issuer-related information
for (const [key, value] of unprotected_header_receipt.entries()) {
    console.log(`\nUnprotected Key ${key}:`)
    console.log('  Type:', typeof value)
    console.log('  Value:', value)
} 