import * as fs from 'fs'
import { verify_receipt_signature } from './src/drafts/draft-birkholz-cose-receipts-ccf-profile/verify_receipt'

async function testSignatureVerification() {
    console.log('Testing signature verification with SCRAPI resolution...')

    // Load the actual receipt
    const actualReceipt = fs.readFileSync('./tests/draft-ietf-scitt-architecture/actual-receipt.cbor')

    try {
        console.log('Verifying receipt signature...')
        const result = await verify_receipt_signature(actualReceipt)

        console.log('Signature verification result:', result ? '✅ PASS' : '❌ FAIL')

        if (result) {
            console.log('✅ Receipt signature verified successfully using SCRAPI-resolved transparency config')
        } else {
            console.log('❌ Receipt signature verification failed')
        }

    } catch (error) {
        console.error('Error during signature verification:', error)
    }
}

testSignatureVerification().catch(console.error) 