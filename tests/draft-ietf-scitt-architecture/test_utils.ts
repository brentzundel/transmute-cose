
import * as cose from '../../src'
import * as fs from 'fs'

import { create_sqlite_log } from '../draft-ietf-cose-merkle-tree-proofs/test_log'

type create_transparency_params = {
    website: string
    database: string
}

// ============================================================================
// Receipt Analysis and Extraction Utilities
// ============================================================================

/**
 * Extract the actual receipt from the transparent statement
 */
export function extractActualReceipt(): Uint8Array | null {
    console.log('=== Extracting Actual Receipt ===')

    const transparent_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose'
    const transparent_statement = fs.readFileSync(transparent_statement_path)

    try {
        // Decode the transparent statement
        const decoded = cose.cbor.decode(transparent_statement)

        // Get the unprotected header where receipts are stored
        const unprotected_header = decoded.value[1]

        if (unprotected_header && typeof unprotected_header.get === 'function') {
            const receipts = unprotected_header.get(cose.draft_headers.receipts)

            if (receipts && Array.isArray(receipts) && receipts.length > 0) {
                const actual_receipt = receipts[0]
                console.log(`Extracted receipt: ${actual_receipt.length} bytes`)

                // Try to decode the receipt to understand its structure
                try {
                    const receipt_decoded = cose.cbor.decode(actual_receipt)
                    console.log('Receipt structure:', receipt_decoded)

                    // Save the receipt to a file for use in tests
                    const receipt_path = './tests/draft-ietf-scitt-architecture/actual-receipt.cbor'
                    fs.writeFileSync(receipt_path, actual_receipt)
                    console.log(`Receipt saved to: ${receipt_path}`)

                    return actual_receipt
                } catch (error) {
                    console.log('Receipt not valid CBOR:', error)
                    return actual_receipt
                }
            }
        }

        console.log('No receipts found in transparent statement')
        return null

    } catch (error) {
        console.error('Error extracting receipt:', error)
        return null
    }
}

/**
 * Analyze the transparent statement to extract actual receipts
 */
export function analyzeTransparentStatement(): void {
    console.log('=== Analyzing Transparent Statement ===')

    const transparent_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose'
    const transparent_statement = fs.readFileSync(transparent_statement_path)

    console.log(`Statement size: ${transparent_statement.length} bytes`)

    try {
        // Decode the transparent statement
        const decoded = cose.cbor.decode(transparent_statement)
        console.log(`COSE structure: ${decoded.value.length} elements`)

        // Analyze the header
        const header = cose.cbor.decode(decoded.value[0])
        console.log('Protected header:', header)

        // Check for unprotected header (where receipts would be)
        const unprotected_header = decoded.value[1]
        console.log('Unprotected header:', unprotected_header)

        // Look for receipts in unprotected header
        if (unprotected_header && typeof unprotected_header.get === 'function') {
            const receipts = unprotected_header.get(cose.draft_headers.receipts)
            console.log('Receipts found:', receipts)

            if (receipts && Array.isArray(receipts)) {
                console.log(`Found ${receipts.length} receipts`)

                for (let i = 0; i < receipts.length; i++) {
                    const receipt = receipts[i]
                    console.log(`Receipt ${i + 1}:`, receipt)
                    console.log(`Receipt ${i + 1} size: ${receipt.length} bytes`)

                    // Try to decode as CBOR to see structure
                    try {
                        const receipt_decoded = cose.cbor.decode(receipt)
                        console.log(`Receipt ${i + 1} decoded:`, receipt_decoded)
                    } catch (error) {
                        console.log(`Receipt ${i + 1} not valid CBOR:`, error)
                    }
                }
            }
        }

        // Also check the payload and signature
        console.log('Payload (index 2):', decoded.value[2])
        console.log('Signature (index 3):', decoded.value[3])

    } catch (error) {
        console.error('Error analyzing transparent statement:', error)
    }
}

/**
 * Analyze the actual receipt structure in detail
 */
export function analyzeActualReceipt(): void {
    console.log('=== Analyzing Actual Receipt Structure ===')

    const transparent_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose'
    const transparent_statement = fs.readFileSync(transparent_statement_path)

    try {
        // Decode the transparent statement
        const decoded = cose.cbor.decode(transparent_statement)
        const unprotected_header = decoded.value[1]

        if (unprotected_header && typeof unprotected_header.get === 'function') {
            const receipts = unprotected_header.get(cose.draft_headers.receipts)

            if (receipts && Array.isArray(receipts) && receipts.length > 0) {
                const actual_receipt = receipts[0]
                console.log(`Actual receipt size: ${actual_receipt.length} bytes`)

                // Decode the receipt
                const receipt_decoded = cose.cbor.decode(actual_receipt)
                console.log('Receipt CBOR structure:', receipt_decoded)

                // Analyze the structure in detail
                if (receipt_decoded.tag === 18) {
                    console.log('Receipt has tag 18 (COSE_Sign1)')
                    const receipt_value = receipt_decoded.value
                    console.log('Receipt value length:', receipt_value.length)

                    for (let i = 0; i < receipt_value.length; i++) {
                        const element = receipt_value[i]
                        console.log(`Element ${i}:`, element)

                        if (element instanceof Map) {
                            console.log(`  Element ${i} is a Map with ${element.size} entries`)
                            for (const [key, value] of element.entries()) {
                                console.log(`    Key ${key}:`, value)
                            }
                        } else if (element instanceof Uint8Array) {
                            console.log(`  Element ${i} is Uint8Array with ${element.length} bytes`)
                            console.log(`    Hex: ${Buffer.from(element).toString('hex')}`)
                        } else if (element === null) {
                            console.log(`  Element ${i} is null`)
                        } else {
                            console.log(`  Element ${i} type:`, typeof element)
                        }
                    }

                    // Try to understand the structure
                    console.log('\n=== Receipt Structure Analysis ===')
                    console.log('This appears to be a COSE_Sign1 structure with:')
                    console.log('- Element 0: Protected header (Uint8Array)')
                    console.log('- Element 1: Unprotected header (Map)')
                    console.log('- Element 2: Payload (null for detached signature)')
                    console.log('- Element 3: Signature (Uint8Array)')

                    // Try to decode the protected header
                    if (receipt_value[0] instanceof Uint8Array) {
                        try {
                            const protected_header = cose.cbor.decode(receipt_value[0])
                            console.log('Protected header decoded:', protected_header)
                        } catch (error) {
                            console.log('Could not decode protected header:', error)
                        }
                    }

                    // Analyze the unprotected header
                    if (receipt_value[1] instanceof Map) {
                        console.log('Unprotected header entries:')
                        for (const [key, value] of receipt_value[1].entries()) {
                            console.log(`  Key ${key}:`, value)
                        }
                    }
                }
            }
        }

    } catch (error) {
        console.error('Error analyzing receipt:', error)
    }
}

// ============================================================================
// Transparency Service Utilities
// ============================================================================

export const create_software_producer = async ({ website, product }: { website: string, product: string }) => {
    const privateKeyJwk = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
        type: "application/jwk+json",
        algorithm: "ES256"
    })
    const publicKeyJwk = cose.public_from_private({
        key: privateKeyJwk,
        type: "application/jwk+json"
    })
    const signer = cose.hash.signer({
        remote: cose.crypto.signer({
            privateKeyJwk
        })
    })
    const verifier = cose.detached
        .verifier({
            resolver: {
                resolve: async () => {
                    return publicKeyJwk
                }
            }
        })


    return { website, product, signer, verifier, public_key: publicKeyJwk }
}

export const create_transparency_service = async ({ website, database }: create_transparency_params) => {


    const privateKeyJwk = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
        type: "application/jwk+json",
        algorithm: "ES256"
    })

    const publicKeyJwk = cose.public_from_private({
        key: privateKeyJwk,
        type: "application/jwk+json"
    })

    const signer = cose.detached.signer({
        remote: cose.crypto.signer({
            privateKeyJwk
        })
    })

    const verifier = cose.detached
        .verifier({
            resolver: {
                resolve: async () => {
                    return publicKeyJwk
                }
            }
        })

    const { log, db } = create_sqlite_log(database)

    const register_signed_statement = async (signed_statement: Uint8Array) => {
        // registration policy goes here...
        // for this test, we accept everything

        const record = await cose.prepare_for_inclusion(signed_statement)
        log.write_record(record)

        const root = log.root()
        const index = log.size()
        const decoded = cose.cbor.decode(signed_statement)
        const signed_statement_header = cose.cbor.decode(decoded.value[0])
        const signed_statement_claims = signed_statement_header.get(cose.header.cwt_claims)
        const inclusion_proof = log.inclusion_proof(index, index - 1)
        return signer.sign({
            protectedHeader: cose.ProtectedHeader([
                [cose.header.kid, publicKeyJwk.kid],
                [cose.header.alg, cose.algorithm.es256],
                [cose.draft_headers.verifiable_data_structure, cose.verifiable_data_structures.rfc9162_sha256],
                [cose.header.cwt_claims, cose.CWTClaims([

                    [cose.cwt_claims.iss, website], // issuer notary
                    // receipt subject is statement subject.
                    // ... could be receipts have different subject id
                    [cose.cwt_claims.sub, signed_statement_claims.get(cose.cwt_claims.sub)]
                ])]
            ]),
            unprotectedHeader: cose.UnprotectedHeader([
                [cose.draft_headers.verifiable_data_proofs, cose.VerifiableDataStructureProofs([
                    [cose.rfc9162_sha256_proof_types.inclusion, [inclusion_proof]],
                ])]
            ]),
            payload: root
        })
    }

    return {
        website,
        db,
        signer,
        verifier,
        log,
        register_signed_statement,
        public_key: publicKeyJwk
    }

}

export const verify_transparent_statement = async (statement_hash: Uint8Array, signature: Uint8Array, config: any) => {
    // first, we verify the signed statement
    const verifier = cose.detached.verifier(config)
    const verified_statement = await verifier.verify({
        coseSign1: signature,
        payload: statement_hash
    })
    const decoded_signed_statement = cose.cbor.decode(signature)
    const signed_statement_claims = cose.cbor.decode(decoded_signed_statement.value[0]).get(cose.header.cwt_claims)
    const result = {
        issuer: signed_statement_claims.get(cose.cwt_claims.iss),
        subject: signed_statement_claims.get(cose.cwt_claims.sub),
        verified_statement_hash: cose.to_hex(verified_statement),
        receipts: []
    } as Record<string, any>
    const decoded_signature = cose.cbor.decode(signature)
    const receipts = decoded_signature.value[1].get(cose.draft_headers.receipts)
    // next verify each receipt
    for (const receipt of receipts) {
        const decoded_receipt = cose.cbor.decode(receipt)
        const proofs = decoded_receipt.value[1].get(cose.draft_headers.verifiable_data_proofs)
        // first proof of inclusion only
        const [[size, index, inclusion_path]] = proofs.get(cose.rfc9162_sha256_proof_types.inclusion)
        // we need to remove receipts in order to compute leaf hash
        const record = await cose.prepare_for_inclusion(signature)
        const record_hash = config.tree_hasher.hash_leaf(record)
        const root = cose.root_from_record_proof(config.tree_hasher, inclusion_path, size, index, record_hash)
        const verified_root = await verifier.verify({
            coseSign1: receipt,
            payload: Buffer.from(root)
        })
        const receipt_claims = cose.cbor.decode(decoded_receipt.value[0]).get(cose.header.cwt_claims)
        result.receipts.push({
            issuer: receipt_claims.get(cose.cwt_claims.iss),
            subject: receipt_claims.get(cose.cwt_claims.sub),
            verified_root: cose.to_hex(verified_root)
        })
    }
    return result
}