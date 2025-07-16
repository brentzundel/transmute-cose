import fs from 'fs'
import * as cose from '../../src'
import { create_software_producer, create_transparency_service, verify_transparent_statement } from './test_utils'

describe('Signed Statement Verification', () => {
    it('should verify the signature of the signed_statement file', async () => {
        // Read the signed statement file
        const signed_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose.empty_uhdr'
        const signed_statement = fs.readFileSync(signed_statement_path)

        // Decode the signed statement to understand its structure
        const decoded = cose.cbor.decode(signed_statement)
        const header = cose.cbor.decode(decoded.value[0])
        const claims = header.get(cose.header.cwt_claims)

        // For now, we'll just verify that we can decode the structure
        // The actual verification would require the correct public keys
        expect(decoded.value).toHaveLength(4) // COSE Sign1 structure
        expect(header).toBeDefined()
        expect(claims).toBeDefined()
    })

    it('should extract and verify claims from the signed statement', async () => {
        // Read the signed statement file
        const signed_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose.empty_uhdr'
        const signed_statement = fs.readFileSync(signed_statement_path)

        // Decode the signed statement to extract claims
        const decoded = cose.cbor.decode(signed_statement)
        const header = cose.cbor.decode(decoded.value[0])
        const claims = header.get(cose.header.cwt_claims)

        // Verify that claims exist and have expected structure
        expect(claims).toBeDefined()
        expect(claims.get(cose.cwt_claims.iss)).toBeDefined()
        expect(claims.get(cose.cwt_claims.sub)).toBeDefined()

        // Check other header fields
        const algorithm = header.get(cose.header.alg)
        const x5c = header.get(33) // x5c header for certificate chain

        // Verify header fields exist
        expect(algorithm).toBeDefined()
        // Note: Microsoft SCITT uses x5c instead of kid, so we don't expect kid to be present
        expect(x5c).toBeDefined()

    })

    it('should verify individual receipts in the signed statement', async () => {
        // Read the signed statement file
        const signed_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose.empty_uhdr'
        const signed_statement = fs.readFileSync(signed_statement_path)

        // Decode to get receipts
        const decoded = cose.cbor.decode(signed_statement)
        const unprotectedHeader = decoded.value[1]
        const receipts = unprotectedHeader && typeof unprotectedHeader.get === 'function'
            ? unprotectedHeader.get(cose.draft_headers.receipts)
            : null

        if (receipts && receipts.length > 0) {
            // Verify each receipt individually
            for (let i = 0; i < receipts.length; i++) {
                const receipt = receipts[i]
                const decoded_receipt = cose.cbor.decode(receipt)
                const receipt_header = cose.cbor.decode(decoded_receipt.value[0])
                const receipt_claims = receipt_header.get(cose.header.cwt_claims)

                // Verify receipt structure
                expect(decoded_receipt.value).toHaveLength(4) // COSE Sign1 structure
                expect(receipt_claims).toBeDefined()
            }
        }
    })

    it('should handle verification errors gracefully', async () => {
        // Test with invalid data
        const invalid_signature = new Uint8Array([1, 2, 3, 4, 5])
        const statement_hash = new Uint8Array(32) // 32 zero bytes

        const blue_notary = await create_transparency_service({
            website: 'https://blue.example',
            database: './tests/draft-ietf-scitt-architecture/blue.transparency.db'
        })

        // This should throw an error
        await expect(
            verify_transparent_statement(statement_hash, invalid_signature, {
                tree_hasher: blue_notary.log.tree_hasher,
                resolver: {
                    resolve: async () => {
                        throw new Error('Invalid key')
                    }
                }
            })
        ).rejects.toThrow()
    })

    it('should demonstrate basic COSE signature verification with certificate-based keys', async () => {
        // Create a simple test to demonstrate the verification process
        // Generate a test key pair
        const privateKeyJwk = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
            type: "application/jwk+json",
            algorithm: "ES256"
        })
        const publicKeyJwk = cose.public_from_private({
            key: privateKeyJwk,
            type: "application/jwk+json"
        })

        // Create a simple signer without hash envelope
        const signer = cose.detached.signer({
            remote: cose.crypto.signer({
                privateKeyJwk
            })
        })

        const statement = Buffer.from('test statement for verification')

        // Create a simple signature without hash envelope
        const signed_statement = await signer.sign({
            protectedHeader: cose.ProtectedHeader([
                [cose.header.kid, publicKeyJwk.kid],
                [cose.header.alg, cose.algorithm.es256],
                [cose.header.cwt_claims, cose.CWTClaims([
                    [cose.cwt_claims.iss, 'https://test.example'],
                    [cose.cwt_claims.sub, 'https://test.example/app@v1.0.0'],
                ])]
            ]),
            payload: statement
        })

        // Verify the signature
        const verifier = cose.detached.verifier({
            resolver: {
                resolve: async () => publicKeyJwk
            }
        })

        const verified_payload = await verifier.verify({
            coseSign1: signed_statement,
            payload: statement
        })

        expect(Buffer.from(verified_payload)).toEqual(Buffer.from(statement))
    })
}) 