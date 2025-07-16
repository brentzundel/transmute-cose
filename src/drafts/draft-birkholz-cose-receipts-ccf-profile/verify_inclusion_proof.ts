import * as cbor from '../../cbor'
import { CCFTree, CCFInclusionProof } from './ccf_tree'

export interface CCFReceipt {
    signature: Uint8Array
    inclusion_proof: CCFInclusionProof
    root_hash: Uint8Array
    service_id: string
    cert: Uint8Array
}

/**
 * Verify CCF inclusion proof
 * Based on CCF Python implementation: https://github.com/microsoft/CCF/blob/7e150f4df3cbf8710226cb8da935c14fcaddbe79/python/src/ccf/cose.py#L206
 */
export function verify_inclusion_proof(
    leaf_hash: Uint8Array,
    proof: CCFInclusionProof,
    root_hash: Uint8Array
): boolean {
    return CCFTree.verify_inclusion_proof(leaf_hash, proof, root_hash)
}

/**
 * Derive leaf index from CCF inclusion proof structure
 * According to IETF draft: "the list of left-or-right bits can be treated as the binary decomposition of the index"
 */
function derive_leaf_index_from_proof(proof_array: any[]): number {
    let index = 0
    for (let i = 0; i < proof_array.length; i++) {
        const [is_left, hash] = proof_array[i]
        if (!is_left) {
            // If not left, add 2^i to the index
            index += Math.pow(2, i)
        }
    }
    return index
}

/**
 * Decode CCF receipt from CBOR
 * Handles real CCF receipt structure from Microsoft SCITT according to IETF draft
 */
export function decode_ccf_receipt(receipt_cbor: Uint8Array): CCFReceipt {
    const decoded = cbor.decode(receipt_cbor)

    // Handle the actual receipt structure (COSE_Sign1 with tag 18)
    if (decoded.tag === 18) {
        const receipt_value = decoded.value
        // Extract protected header
        const protected_header = cbor.decode(receipt_value[0])
        // Extract unprotected header
        const unprotected_header = receipt_value[1]
        // Extract signature
        const signature = receipt_value[3]

        // Extract inclusion proof from unprotected header (key 396)
        const ccf_proof_map = unprotected_header.get(396)
        if (!ccf_proof_map || typeof ccf_proof_map.get !== 'function') {
            throw new Error('No CCF inclusion proof map found in receipt')
        }
        // The inclusion proof array is under key -1
        const inclusion_proof_array = ccf_proof_map.get(-1)
        if (!Array.isArray(inclusion_proof_array) || inclusion_proof_array.length === 0) {
            throw new Error('No inclusion proof array found in receipt')
        }
        // The first element is a CBOR map with proof fields
        let proof_map = inclusion_proof_array[0]
        if (proof_map instanceof Uint8Array) {
            proof_map = cbor.decode(proof_map)
        }

        // Extract fields from the proof map according to IETF draft structure
        // Key 1 contains the ccf-leaf: [internal-transaction-hash, internal-evidence, data-hash]
        const ccf_leaf = proof_map.get(1)
        if (!Array.isArray(ccf_leaf) || ccf_leaf.length !== 3) {
            throw new Error('Invalid ccf-leaf structure in proof')
        }

        const internal_transaction_hash = new Uint8Array(ccf_leaf[0])
        const internal_evidence = ccf_leaf[1] // string
        const data_hash = new Uint8Array(ccf_leaf[2])

        // Key 2 contains the proof array: [[left: bool, hash: bstr], ...]
        const proof_array = proof_map.get(2)
        if (!Array.isArray(proof_array)) {
            throw new Error('Invalid proof array structure')
        }

        // Extract proof hashes and derive leaf index
        const proof_hashes = proof_array.map((item: any) => {
            if (!Array.isArray(item) || item.length !== 2 || typeof item[0] !== 'boolean') {
                throw new Error('Invalid proof hash structure')
            }
            return new Uint8Array(item[1])
        })

        // Derive leaf index from proof structure (binary decomposition)
        const leaf_index = derive_leaf_index_from_proof(proof_array)
        const tree_size = proof_array.length

        // Extract service information from protected header
        const claims = protected_header.get(15) // CWT claims
        const service_id = claims ? claims.get(1) || 'unknown' : 'unknown'

        return {
            signature: new Uint8Array(signature),
            inclusion_proof: {
                leaf_index: leaf_index,
                tree_size: tree_size,
                proof: proof_hashes
            },
            root_hash: data_hash, // Use data_hash as root_hash (this is the leaf hash)
            service_id: service_id,
            cert: new Uint8Array(0) // Certificate not present in this structure
        }
    }
    // Fallback to original CCF receipt structure
    const [signature, inclusion_proof_data, root_hash, service_id, cert] = decoded.value
    // Decode inclusion proof
    const inclusion_proof: CCFInclusionProof = {
        leaf_index: inclusion_proof_data[0],
        tree_size: inclusion_proof_data[1],
        proof: inclusion_proof_data[2].map((hash: any) => new Uint8Array(hash))
    }
    return {
        signature: new Uint8Array(signature),
        inclusion_proof,
        root_hash: new Uint8Array(root_hash),
        service_id: service_id.toString(),
        cert: new Uint8Array(cert)
    }
}

/**
 * Verify CCF receipt structure
 */
export function verify_ccf_receipt_structure(receipt: CCFReceipt): boolean {
    try {
        // Verify required fields exist
        if (!receipt.signature || !receipt.inclusion_proof || !receipt.root_hash || !receipt.service_id) {
            console.log('Missing required fields')
            return false
        }
        // Verify inclusion proof structure
        if (typeof receipt.inclusion_proof.leaf_index !== 'number' || typeof receipt.inclusion_proof.tree_size !== 'number') {
            console.log('Invalid leaf_index or tree_size types:', typeof receipt.inclusion_proof.leaf_index, typeof receipt.inclusion_proof.tree_size)
            return false
        }
        if (receipt.inclusion_proof.leaf_index < 0 || receipt.inclusion_proof.tree_size <= 0) {
            console.log('Invalid leaf_index or tree_size values:', receipt.inclusion_proof.leaf_index, receipt.inclusion_proof.tree_size)
            return false
        }
        if (receipt.inclusion_proof.leaf_index >= receipt.inclusion_proof.tree_size) {
            console.log('Leaf index >= tree size:', receipt.inclusion_proof.leaf_index, '>=', receipt.inclusion_proof.tree_size)
            return false
        }
        // Verify proof array
        if (!Array.isArray(receipt.inclusion_proof.proof)) {
            console.log('Proof is not an array')
            return false
        }
        // Verify all proof elements are valid hashes
        for (let i = 0; i < receipt.inclusion_proof.proof.length; i++) {
            const hash = receipt.inclusion_proof.proof[i]
            if (!(hash instanceof Uint8Array) || hash.length !== 32) {
                console.log(`Invalid proof hash at index ${i}:`, typeof hash, hash?.length)
                return false
            }
        }
        // Verify root hash
        if (!(receipt.root_hash instanceof Uint8Array) || receipt.root_hash.length !== 32) {
            console.log('Invalid root hash:', typeof receipt.root_hash, receipt.root_hash?.length)
            return false
        }
        return true
    } catch (error) {
        console.error('CCF receipt structure verification failed:', error)
        return false
    }
} 