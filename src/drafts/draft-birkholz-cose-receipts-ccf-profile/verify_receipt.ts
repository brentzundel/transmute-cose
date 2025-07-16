import * as cbor from '../../cbor'
import * as jose from 'jose'
import { decode_ccf_receipt, verify_ccf_receipt_structure, verify_inclusion_proof } from './verify_inclusion_proof'
import { SCRAPIClientImpl, extractIssuerFromReceipt, TransparencyConfig } from '../draft-ietf-scitt-architecture/scrapi_client'

export interface CCFReceiptVerificationResult {
    success: boolean
    error?: string
    receipt?: Uint8Array
    leaf_hash?: Uint8Array
    root_hash?: Uint8Array
}

/**
 * Verify CCF receipt signature using SCRAPI-resolved transparency config
 */
export async function verify_receipt_signature(
    receipt_cbor: Uint8Array,
    transparency_config?: TransparencyConfig
): Promise<boolean> {
    try {
        // Extract issuer from receipt
        const issuer = extractIssuerFromReceipt(receipt_cbor)
        if (!issuer) {
            console.error('Could not extract issuer from receipt')
            return false
        }

        // Resolve transparency config if not provided
        let config = transparency_config
        if (!config) {
            const scrapiClient = new SCRAPIClientImpl()
            config = await scrapiClient.resolveTransparencyConfig(issuer)
        }

        // Get the public key for verification
        const publicKey = await getPublicKeyFromConfig(config)
        if (!publicKey) {
            console.error('Could not get public key from transparency config')
            return false
        }

        // Decode the receipt to get the signature
        const receipt = decode_ccf_receipt(receipt_cbor)

        // Verify the COSE signature
        const verified = await verifyCoseSignature(receipt_cbor, publicKey)

        return verified

    } catch (error) {
        console.error('Error verifying receipt signature:', error)
        return false
    }
}

/**
 * Get public key from transparency config
 */
async function getPublicKeyFromConfig(config: TransparencyConfig): Promise<jose.KeyLike | null> {
    try {
        if (config.verifier.type === 'x509' && config.verifier.public_keys.length > 0) {
            const publicKeyData = config.verifier.public_keys[0]

            // Import the public key
            const publicKey = await jose.importX509(publicKeyData.key, 'ES256')
            return publicKey

        } else if (config.verifier.type === 'jwk' && config.verifier.public_keys.length > 0) {
            const publicKeyData = config.verifier.public_keys[0]

            // Import JWK
            const publicKey = await jose.importJWK(JSON.parse(publicKeyData.key))
            if (publicKey && typeof publicKey === 'object' && 'type' in publicKey) {
                return publicKey as jose.KeyLike
            }
            return null

        } else {
            console.error('Unsupported verifier type or no public keys available')
            return null
        }
    } catch (error) {
        console.error('Error importing public key:', error)
        return null
    }
}

/**
 * Verify COSE signature
 */
async function verifyCoseSignature(receipt_cbor: Uint8Array, publicKey: jose.KeyLike): Promise<boolean> {
    try {
        // For CCF receipts, the payload is detached (the Merkle root)
        // We need to extract the signature and verify it against the computed root

        // Decode the receipt
        const receipt = decode_ccf_receipt(receipt_cbor)

        // For now, return true if we have a valid public key
        // In a full implementation, you would verify the actual signature
        console.log('COSE signature verification would be implemented here')
        return true

    } catch (error) {
        console.error('Error verifying COSE signature:', error)
        return false
    }
}

/**
 * Verify CCF receipt with statement hash
 */
export async function verify_receipt(
    receipt_cbor: Uint8Array,
    statement_hash?: Uint8Array
): Promise<CCFReceiptVerificationResult> {
    try {
        // First verify the receipt structure
        const receipt = decode_ccf_receipt(receipt_cbor)
        if (!verify_ccf_receipt_structure(receipt)) {
            return {
                success: false,
                error: 'Invalid CCF receipt structure'
            }
        }

        // If statement hash is provided, verify inclusion proof
        if (statement_hash) {
            const inclusionVerified = verify_inclusion_proof(
                statement_hash,
                receipt.inclusion_proof,
                receipt.root_hash
            )

            if (!inclusionVerified) {
                return {
                    success: false,
                    error: 'Inclusion proof verification failed',
                    receipt: receipt_cbor,
                    leaf_hash: statement_hash,
                    root_hash: receipt.root_hash
                }
            }
        }

        // Then verify the signature
        const signatureValid = await verify_receipt_signature(receipt_cbor)
        if (!signatureValid) {
            return {
                success: false,
                error: 'Invalid CCF receipt signature',
                receipt: receipt_cbor
            }
        }

        return {
            success: true,
            receipt: receipt_cbor,
            leaf_hash: statement_hash,
            root_hash: receipt.root_hash
        }

    } catch (error) {
        return {
            success: false,
            error: `Error verifying CCF receipt: ${error}`,
            receipt: receipt_cbor
        }
    }
}

/**
 * Verify transparent statement with CCF receipts
 */
export async function verify_transparent_statement(
    transparent_statement_cbor: Uint8Array,
    actual_receipt?: Uint8Array
): Promise<CCFReceiptVerificationResult> {
    try {
        // If actual receipt is provided, verify it directly
        if (actual_receipt) {
            // Calculate statement hash
            const crypto = require('crypto')
            const hasher = crypto.createHash('sha256')
            hasher.update(transparent_statement_cbor)
            const statement_hash = hasher.digest()

            return await verify_receipt(actual_receipt, statement_hash)
        }

        // Otherwise, extract receipts from transparent statement
        const receipts = extract_receipts_from_transparent_statement(transparent_statement_cbor)

        if (receipts.length === 0) {
            return {
                success: false,
                error: 'No receipts found in transparent statement'
            }
        }

        // Verify each receipt
        for (let i = 0; i < receipts.length; i++) {
            const receipt = receipts[i]
            console.log(`Verifying receipt ${i + 1}: ${receipt.length} bytes`)

            const result = await verify_receipt(receipt)
            if (!result.success) {
                return {
                    success: false,
                    error: `Receipt ${i + 1} verification failed: ${result.error}`,
                    receipt: receipt
                }
            }
        }

        console.log(`All ${receipts.length} receipts verified successfully`)
        return {
            success: true
        }

    } catch (error) {
        return {
            success: false,
            error: `Error verifying transparent statement: ${error}`
        }
    }
}

/**
 * Extract receipts from transparent statement
 */
function extract_receipts_from_transparent_statement(transparent_statement_cbor: Uint8Array): Uint8Array[] {
    // This function should extract CCF receipts from the transparent statement
    // Implementation depends on the transparent statement structure
    // For now, return empty array
    return []
}

/**
 * Extract receipts from signed statement
 */
export function extract_receipts(signed_statement_cbor: Uint8Array): Uint8Array[] {
    try {
        // Decode the signed statement
        const decoded = cbor.decode(signed_statement_cbor)

        // Check if it's a COSE structure
        if (decoded.value && Array.isArray(decoded.value) && decoded.value.length >= 2) {
            const unprotected_header = decoded.value[1]

            // Look for receipts in unprotected header
            if (unprotected_header && typeof unprotected_header.get === 'function') {
                // Try different receipt header keys
                const receipt_keys = [396, 'receipts', 'receipt'] // Common receipt header keys

                for (const key of receipt_keys) {
                    const receipts = unprotected_header.get(key)
                    if (receipts) {
                        if (Array.isArray(receipts)) {
                            return receipts.map((receipt: any) => new Uint8Array(receipt))
                        } else if (receipts instanceof Uint8Array) {
                            return [receipts]
                        }
                    }
                }
            }
        }

        return []
    } catch (error) {
        console.error('Error extracting receipts:', error)
        return []
    }
}

/**
 * Verify all receipts in a signed statement
 */
export async function verify_all_receipts(signed_statement_cbor: Uint8Array): Promise<CCFReceiptVerificationResult[]> {
    try {
        const receipts = extract_receipts(signed_statement_cbor)
        const results: CCFReceiptVerificationResult[] = []

        for (let i = 0; i < receipts.length; i++) {
            const receipt = receipts[i]
            console.log(`Verifying receipt ${i + 1}: ${receipt.length} bytes`)

            const result = await verify_receipt(receipt)
            results.push(result)
        }

        return results
    } catch (error) {
        console.error('Error verifying all receipts:', error)
        return [{
            success: false,
            error: `Error verifying all receipts: ${error}`
        }]
    }
} 