import * as https from 'https'
import * as http from 'http'
import * as cbor from '../../cbor'

export interface TransparencyConfig {
    issuer: string
    service_id: string
    verifier: {
        type: string
        public_keys: Array<{
            kid: string
            key: string // PEM or JWK
        }>
    }
    tree_algorithm: string
    hash_algorithm: string
}

export interface SCRAPIClient {
    resolveTransparencyConfig(issuer: string): Promise<TransparencyConfig>
}

/**
 * SCRAPI Client implementation
 * Based on IETF draft: https://ietf-wg-scitt.github.io/draft-ietf-scitt-scrapi/draft-ietf-scitt-scrapi.html
 */
export class SCRAPIClientImpl implements SCRAPIClient {

    /**
     * Resolve transparency configuration for an issuer
     * Follows the SCRAPI specification for transparency config resolution
     */
    async resolveTransparencyConfig(issuer: string): Promise<TransparencyConfig> {
        try {
            // For Microsoft CCF, the issuer is the service endpoint
            // We need to construct the transparency config URL
            const baseUrl = this.getBaseUrl(issuer)
            const configUrl = `${baseUrl}/.well-known/scitt/transparency-config`

            console.log(`Resolving transparency config from: ${configUrl}`)

            const response = await this.makeRequest(configUrl)

            if (!response.ok) {
                throw new Error(`Failed to fetch transparency config: ${response.status} ${response.statusText}`)
            }

            const config = await response.json()

            // Validate the config structure
            if (!config.issuer || !config.service_id || !config.verifier) {
                throw new Error('Invalid transparency config structure')
            }

            return config as TransparencyConfig

        } catch (error) {
            console.error('Error resolving transparency config:', error)

            // For now, return a mock config for testing
            // In production, this should fail if the config cannot be resolved
            return this.getMockTransparencyConfig(issuer)
        }
    }

    /**
     * Get base URL from issuer
     */
    private getBaseUrl(issuer: string): string {
        // Handle different issuer formats
        if (issuer.startsWith('did:')) {
            // For DID-based issuers, we might need to resolve the DID first
            throw new Error('DID-based issuer resolution not yet implemented')
        } else if (issuer.includes('confidential-ledger.azure.com')) {
            // For Azure Confidential Ledger, construct the service URL
            return `https://${issuer}`
        } else {
            // Assume it's already a full URL
            return issuer.startsWith('http') ? issuer : `https://${issuer}`
        }
    }

    /**
     * Make HTTP request
     */
    private async makeRequest(url: string): Promise<Response> {
        return fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'User-Agent': 'transmute-cose/1.0'
            }
        })
    }

    /**
     * Get mock transparency config for testing
     * This should be replaced with actual config resolution in production
     */
    private getMockTransparencyConfig(issuer: string): TransparencyConfig {
        return {
            issuer: issuer,
            service_id: issuer,
            verifier: {
                type: 'x509',
                public_keys: [
                    {
                        kid: 'mock-key-id',
                        key: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...mock-key...
-----END PUBLIC KEY-----`
                    }
                ]
            },
            tree_algorithm: 'CCF_LEDGER_SHA256',
            hash_algorithm: 'SHA256'
        }
    }
}

/**
 * Extract issuer from CCF receipt
 */
export function extractIssuerFromReceipt(receipt_cbor: Uint8Array): string | null {
    try {
        const decoded = cbor.decode(receipt_cbor)

        if (decoded.tag === 18) {
            const protected_header = cbor.decode(decoded.value[0])
            const claims = protected_header.get(15) // CWT claims

            if (claims && claims instanceof Map) {
                const issuer = claims.get(1) // iss claim
                if (typeof issuer === 'string') {
                    return issuer
                }
            }
        }

        return null
    } catch (error) {
        console.error('Error extracting issuer from receipt:', error)
        return null
    }
} 