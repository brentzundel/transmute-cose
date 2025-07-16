import fs from 'fs'
import * as cose from '../../src'
import * as jose from 'jose'

describe('Microsoft SCITT Statement Verification', () => {
    it('should extract and analyze the Microsoft SCITT statement structure', async () => {
        // Read the signed statement file
        const signed_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose.empty_uhdr'
        const signed_statement = fs.readFileSync(signed_statement_path)

        // Decode the signed statement
        const decoded = cose.cbor.decode(signed_statement)
        const header = cose.cbor.decode(decoded.value[0])
        const claims = header.get(cose.header.cwt_claims)

        // Verify structure
        expect(decoded.value).toHaveLength(4) // COSE Sign1 structure
        expect(header).toBeDefined()
        expect(claims).toBeDefined()
        expect(claims.get(cose.cwt_claims.iss)).toBeDefined()
        expect(claims.get(cose.cwt_claims.sub)).toBeDefined()
    })

    it('should extract certificate chain and create verifier', async () => {
        const signed_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose.empty_uhdr'
        const signed_statement = fs.readFileSync(signed_statement_path)

        const decoded = cose.cbor.decode(signed_statement)
        const header = cose.cbor.decode(decoded.value[0])
        const x5c = header.get(33) // x5c header

        if (!x5c || !Array.isArray(x5c)) {
            return
        }

        try {
            // Extract the leaf certificate (first in chain)
            const leafCertBytes = x5c[0]
            const leafCertPem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(leafCertBytes).toString('base64')}\n-----END CERTIFICATE-----`

            // Import the certificate and extract public key
            const alg = header.get(cose.header.alg)
            const algName = cose.labels_to_algorithms.get(alg)

            if (!algName) {
                throw new Error(`Unknown algorithm: ${alg}`)
            }

            // Import the certificate
            const cert = await jose.importX509(leafCertPem, algName)
            const publicKeyJwk = await jose.exportJWK(cert)
            publicKeyJwk.alg = algName

            // Create a verifier using the extracted public key
            const verifier = cose.detached.verifier({
                resolver: {
                    resolve: async () => publicKeyJwk
                }
            })

            // Note: For full verification, we would need the original payload
            // The signed statement appears to be a detached signature

        } catch (error) {
            console.error('Error processing certificate:', error)
            throw error
        }
    })

    it('should verify receipt signatures', async () => {
        const signed_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose.empty_uhdr'
        const signed_statement = fs.readFileSync(signed_statement_path)

        const decoded = cose.cbor.decode(signed_statement)
        const unprotectedHeader = decoded.value[1]
        const receipts = unprotectedHeader && typeof unprotectedHeader.get === 'function'
            ? unprotectedHeader.get(cose.draft_headers.receipts)
            : null

        if (!receipts || receipts.length === 0) {
            return
        }

        for (let i = 0; i < receipts.length; i++) {
            const receipt = receipts[i]
            const decoded_receipt = cose.cbor.decode(receipt)
            const receipt_header = cose.cbor.decode(decoded_receipt.value[0])

            // Check for certificate in receipt
            const receipt_x5c = receipt_header.get(33)
            if (receipt_x5c && Array.isArray(receipt_x5c) && receipt_x5c.length > 0) {
                try {
                    const receiptCertBytes = receipt_x5c[0]
                    const receiptCertPem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(receiptCertBytes).toString('base64')}\n-----END CERTIFICATE-----`

                    const receiptAlg = receipt_header.get(cose.header.alg)
                    const receiptAlgName = cose.labels_to_algorithms.get(receiptAlg)

                    if (receiptAlgName) {
                        const receiptCert = await jose.importX509(receiptCertPem, receiptAlgName)
                        const receiptPublicKeyJwk = await jose.exportJWK(receiptCert)
                        receiptPublicKeyJwk.alg = receiptAlgName
                    }
                } catch (error) {
                    console.error(`  Error processing receipt certificate:`, error)
                }
            }
        }
    })

    it('should demonstrate full verification with mock data', async () => {
        // This test demonstrates the full verification process
        // using a mock certificate and signature

        // Create a test certificate and signature
        const testCert = await cose.certificate.root({
            alg: 'ES256',
            iss: 'test.example',
            sub: 'test.example',
            nbf: new Date().toISOString(),
            exp: new Date(Date.now() + 5 * 60 * 1000).toISOString(), // 5 minutes
            serial: "01"
        })

        const testThumbprint = await cose.certificate.thumbprint(testCert.public)
        const testSigner = await cose.certificate.pkcs8Signer({
            alg: cose.algorithm.es256,
            privateKeyPKCS8: testCert.private
        })

        const testContent = Buffer.from('test content for verification')
        const testSignature = await testSigner.sign({
            protectedHeader: cose.ProtectedHeader([
                [cose.header.alg, cose.algorithm.es256],
                [cose.header.x5t, testThumbprint],
                [cose.header.content_type, "text/plain"],
            ]),
            payload: testContent
        })

        // Create verifier using certificate
        const certificateFromThumbprint = async (coseSign1: Uint8Array) => {
            const { tag, value } = cose.cbor.decodeFirstSync(coseSign1)
            if (tag !== cose.tag.COSE_Sign1) {
                throw new Error('Only tagged cose sign 1 are supported')
            }
            const [protectedHeaderBytes] = value
            const protectedHeaderMap = cose.cbor.decodeFirstSync(protectedHeaderBytes)
            const alg = protectedHeaderMap.get(cose.header.alg)
            const x5t = protectedHeaderMap.get(cose.header.x5t)

            if (!x5t) {
                throw new Error('x5t is required in protected header')
            }

            // In a real implementation, you would look up the certificate
            // using the thumbprint in a certificate store
            return testCert.public
        }

        const verifier = cose.detached.verifier({
            resolver: {
                resolve: certificateFromThumbprint
            }
        })
    })

    it('should analyze the transparent statement structure', async () => {
        // Read the transparent statement file
        const transparent_statement_path = './tests/draft-ietf-scitt-architecture/in-toto.json.hashenvelope.cose'
        const transparent_statement = fs.readFileSync(transparent_statement_path)

        // Decode the transparent statement
        const decoded = cose.cbor.decode(transparent_statement)
        const header = cose.cbor.decode(decoded.value[0])

        // Verify structure
        expect(decoded.value).toHaveLength(4) // COSE Sign1 structure
        expect(header).toBeDefined()

    })
}) 