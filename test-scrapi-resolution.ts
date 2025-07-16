import * as fs from 'fs'
import { SCRAPIClientImpl, extractIssuerFromReceipt } from './src/drafts/draft-ietf-scitt-architecture/scrapi_client'

async function testSCRAPIResolution() {
    console.log('Testing SCRAPI resolution...')

    // Load the actual receipt
    const actualReceipt = fs.readFileSync('./tests/draft-ietf-scitt-architecture/actual-receipt.cbor')

    // Extract issuer from receipt
    const issuer = extractIssuerFromReceipt(actualReceipt)
    console.log('Extracted issuer:', issuer)

    if (!issuer) {
        console.error('Could not extract issuer from receipt')
        return
    }

    // Try to resolve transparency config
    const scrapiClient = new SCRAPIClientImpl()

    try {
        console.log('\nResolving transparency config...')
        const config = await scrapiClient.resolveTransparencyConfig(issuer)

        console.log('\nTransparency config resolved:')
        console.log('  Issuer:', config.issuer)
        console.log('  Service ID:', config.service_id)
        console.log('  Verifier type:', config.verifier.type)
        console.log('  Public keys:', config.verifier.public_keys.length)
        console.log('  Tree algorithm:', config.tree_algorithm)
        console.log('  Hash algorithm:', config.hash_algorithm)

        // Show first public key (truncated)
        if (config.verifier.public_keys.length > 0) {
            const firstKey = config.verifier.public_keys[0]
            console.log('\nFirst public key:')
            console.log('  KID:', firstKey.kid)
            console.log('  Key (first 100 chars):', firstKey.key.substring(0, 100) + '...')
        }

    } catch (error) {
        console.error('Error resolving transparency config:', error)
    }
}

testSCRAPIResolution().catch(console.error) 