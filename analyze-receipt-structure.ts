import * as fs from 'fs'
import * as cbor from './src/cbor'

// Load the actual receipt
const actualReceipt = fs.readFileSync('./tests/draft-ietf-scitt-architecture/actual-receipt.cbor')

console.log('Actual receipt analysis:')
console.log('Receipt size:', actualReceipt.length, 'bytes')

// Decode the receipt
const receipt_decoded = cbor.decode(actualReceipt)
console.log('\nReceipt decoded structure:')
console.log('  Tag:', receipt_decoded.tag)
console.log('  Value length:', receipt_decoded.value.length)

// Extract protected and unprotected headers
const protected_header = cbor.decode(receipt_decoded.value[0])
const unprotected_header_receipt = receipt_decoded.value[1]
const payload = receipt_decoded.value[2]
const signature = receipt_decoded.value[3]

console.log('\nReceipt protected header keys:', Array.from(protected_header.keys()))
console.log('Receipt unprotected header keys:', Array.from(unprotected_header_receipt.keys()))

// Look for CCF proof data (key 396)
const ccf_proof = unprotected_header_receipt.get(396)
if (ccf_proof) {
    console.log('\nCCF proof found:')
    console.log('  Type:', typeof ccf_proof)
    console.log('  Keys:', Array.from(ccf_proof.keys()))

    // Extract inclusion proof array (key -1)
    const inclusion_proof_array = ccf_proof.get(-1)
    if (inclusion_proof_array) {
        console.log('\nInclusion proof array:')
        console.log('  Length:', inclusion_proof_array.length)
        console.log('  Type:', typeof inclusion_proof_array[0])

        // Analyze the first element
        const first_proof_element = inclusion_proof_array[0]
        if (first_proof_element instanceof Uint8Array) {
            console.log('  First element is Uint8Array, length:', first_proof_element.length)
            console.log('  First element (hex):', Buffer.from(first_proof_element).toString('hex'))

            // Try to decode it
            try {
                const decoded_proof = cbor.decode(first_proof_element)
                console.log('\nDecoded proof element:')
                if (decoded_proof instanceof Map) {
                    for (const [key, value] of decoded_proof.entries()) {
                        console.log(`  Key: ${key}`)
                        printValueRecursive(value, '    ')
                    }
                } else {
                    printValueRecursive(decoded_proof, '  ')
                }
            } catch (error) {
                console.log('  Failed to decode proof element:', error)
            }
        }
    }
}

function printValueRecursive(val: any, indent: string) {
    if (val instanceof Map) {
        console.log(indent + 'Map:')
        for (const [k, v] of val.entries()) {
            console.log(indent + `  Key: ${k}`)
            printValueRecursive(v, indent + '    ')
        }
    } else if (Array.isArray(val)) {
        console.log(indent + `Array (${val.length}):`)
        val.forEach((item, idx) => {
            console.log(indent + `  [${idx}]:`)
            printValueRecursive(item, indent + '    ')
        })
    } else if (val instanceof Uint8Array) {
        console.log(indent + `Uint8Array (${val.length}): ${Buffer.from(val).toString('hex')}`)
    } else {
        console.log(indent + `${typeof val}:`, val)
    }
} 