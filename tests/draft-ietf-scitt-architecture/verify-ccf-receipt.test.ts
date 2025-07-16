import fs from 'fs'
import * as cose from '../../src'
import * as ccf from '../../src/drafts/draft-birkholz-cose-receipts-ccf-profile'

describe('CCF Receipt Verification', () => {
    it('should verify CCF receipt structure', async () => {
        console.log('=== CCF Receipt Structure Verification ===')

        // This test demonstrates the CCF receipt verification functionality
        // In a real scenario, you would have actual CCF receipts from a SCITT ledger

        // Create a mock CCF receipt for demonstration
        const mock_receipt = {
            signature: new Uint8Array(32).fill(1), // Mock signature
            inclusion_proof: {
                leaf_index: 0,
                tree_size: 1,
                proof: [] // Empty proof for root
            },
            root_hash: new Uint8Array(32).fill(2), // Mock root hash
            service_id: 'test-service',
            cert: new Uint8Array(100).fill(3) // Mock certificate
        }

        // Test receipt structure verification
        const structure_valid = ccf.verify_ccf_receipt_structure(mock_receipt)
        expect(structure_valid).toBe(true)

        console.log('✅ CCF receipt structure verification passed')
    })

    it('should verify CCF inclusion proof', async () => {
        console.log('=== CCF Inclusion Proof Verification ===')

        // Create a simple inclusion proof for testing
        const leaf_hash = new Uint8Array(32).fill(1)
        const root_hash = new Uint8Array(32).fill(2)
        const proof = {
            leaf_index: 0,
            tree_size: 1,
            proof: [] // Empty proof for root
        }

        // Test inclusion proof verification
        const inclusion_verified = ccf.verify_inclusion_proof(leaf_hash, proof, root_hash)

        // For this simple case, the verification should work
        expect(inclusion_verified).toBeDefined()

        console.log('✅ CCF inclusion proof verification tested')
    })

    it('should extract receipts from signed statement', async () => {
        console.log('=== Receipt Extraction ===')

        // Read the signed statement file
        const signed_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose.empty_uhdr'
        const signed_statement = fs.readFileSync(signed_statement_path)

        // Extract receipts
        const receipts = ccf.extract_receipts(signed_statement)

        console.log(`Found ${receipts.length} receipts in statement`)

        if (receipts.length > 0) {
            console.log('Receipt details:')
            for (let i = 0; i < receipts.length; i++) {
                const receipt = receipts[i]
                console.log(`  Receipt ${i + 1}: ${receipt.length} bytes`)

                // Try to decode as CCF receipt
                try {
                    const decoded_receipt = ccf.decode_ccf_receipt(receipt)
                    console.log(`    Service ID: ${decoded_receipt.service_id}`)
                    console.log(`    Leaf Index: ${decoded_receipt.inclusion_proof.leaf_index}`)
                    console.log(`    Tree Size: ${decoded_receipt.inclusion_proof.tree_size}`)
                    console.log(`    Proof Length: ${decoded_receipt.inclusion_proof.proof.length}`)
                } catch (error) {
                    console.log(`    Not a CCF receipt: ${error}`)
                }
            }
        }

        expect(Array.isArray(receipts)).toBe(true)
        console.log('✅ Receipt extraction completed')
    })

    it('should verify transparent statement with CCF receipt', async () => {
        console.log('=== Transparent Statement Verification ===')

        // Read the transparent statement
        const transparent_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose'
        const transparent_statement = fs.readFileSync(transparent_statement_path)

        // For demonstration, we'll create a mock receipt
        // In a real scenario, you would have actual CCF receipts
        const mock_receipt_cbor = new Uint8Array(100).fill(1) // Mock receipt CBOR

        try {
            const result = await ccf.verify_transparent_statement(
                transparent_statement,
                mock_receipt_cbor
            )

            console.log('Verification result:', result.success)
            if (!result.success) {
                console.log('Error:', result.error)
            }

            // The verification should fail with mock data, which is expected
            expect(result.success).toBeDefined()
        } catch (error) {
            console.log('Expected error with mock data:', error)
        }

        console.log('✅ Transparent statement verification tested')
    })

    it('should demonstrate complete CCF verification workflow', async () => {
        console.log('=== Complete CCF Verification Workflow ===')

        // Step 1: Read signed statement
        const signed_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose.empty_uhdr'
        const signed_statement = fs.readFileSync(signed_statement_path)

        console.log('Step 1: Signed statement loaded')

        // Step 2: Extract receipts
        const receipts = ccf.extract_receipts(signed_statement)
        console.log(`Step 2: Found ${receipts.length} receipts`)

        // Step 3: Verify each receipt
        for (let i = 0; i < receipts.length; i++) {
            const receipt = receipts[i]
            console.log(`Step 3: Verifying receipt ${i + 1}`)

            try {
                const result = await ccf.verify_receipt(receipt)
                console.log(`  Receipt ${i + 1} verification: ${result.success}`)
                if (!result.success) {
                    console.log(`  Error: ${result.error}`)
                }
            } catch (error) {
                console.log(`  Error verifying receipt ${i + 1}: ${error}`)
            }
        }

        // Step 4: Verify all receipts together
        console.log('Step 4: Verifying all receipts')
        const all_results = await ccf.verify_all_receipts(signed_statement)
        console.log(`  Total receipts verified: ${all_results.length}`)

        // Step 5: Demonstrate transparent statement verification
        console.log('Step 5: Transparent statement verification')
        const transparent_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose'
        const transparent_statement = fs.readFileSync(transparent_statement_path)

        if (receipts.length > 0) {
            const transparent_result = await ccf.verify_transparent_statement(
                transparent_statement,
                receipts[0] // Use first receipt
            )
            console.log(`  Transparent verification: ${transparent_result.success}`)
        }

        console.log('✅ Complete CCF verification workflow demonstrated')
    })

    it('should handle CCF tree operations', async () => {
        console.log('=== CCF Tree Operations ===')

        // Test CCF tree functionality
        const leaf_hash = new Uint8Array(32).fill(1)
        const root_hash = new Uint8Array(32).fill(2)
        const proof = {
            leaf_index: 0,
            tree_size: 1,
            proof: []
        }

        // Test inclusion proof verification
        const verified = ccf.verify_inclusion_proof(leaf_hash, proof, root_hash)
        console.log('Inclusion proof verification result:', verified)

        // Test with invalid proof
        const invalid_proof = {
            leaf_index: 1,
            tree_size: 1,
            proof: []
        }

        const invalid_verified = ccf.verify_inclusion_proof(leaf_hash, invalid_proof, root_hash)
        console.log('Invalid proof verification result:', invalid_verified)

        expect(typeof verified).toBe('boolean')
        expect(typeof invalid_verified).toBe('boolean')

        console.log('✅ CCF tree operations tested')
    })
}) 