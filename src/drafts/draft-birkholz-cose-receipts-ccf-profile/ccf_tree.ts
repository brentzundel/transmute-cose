import * as crypto from 'crypto'

export interface CCFTreeNode {
    level: number
    index: number
}

export interface CCFInclusionProof {
    leaf_index: number
    tree_size: number
    proof: Uint8Array[]
}

export class CCFTree {
    private static readonly HASH_SIZE = 32 // SHA-256 hash size

    /**
     * Verify CCF inclusion proof
     * Based on CCF Python implementation: https://github.com/microsoft/CCF/blob/7e150f4df3cbf8710226cb8da935c14fcaddbe79/python/src/ccf/cose.py#L206
     */
    static verify_inclusion_proof(
        leaf_hash: Uint8Array,
        proof: CCFInclusionProof,
        root_hash: Uint8Array
    ): boolean {
        try {
            const reconstructed_root = this.root_from_inclusion_proof(
                proof.leaf_index,
                proof.tree_size,
                leaf_hash,
                proof.proof
            )
            return this.compare_hashes(reconstructed_root, root_hash)
        } catch (error) {
            // Silently handle verification errors
            return false
        }
    }

    /**
     * Reconstruct root from inclusion proof
     * Based on CCF implementation
     */
    private static root_from_inclusion_proof(
        index: number,
        size: number,
        leaf_hash: Uint8Array,
        proof: Uint8Array[]
    ): Uint8Array {
        if (index >= size) {
            throw new Error(`Index ${index} is beyond tree size ${size}`)
        }

        if (leaf_hash.length !== this.HASH_SIZE) {
            throw new Error(`Leaf hash has unexpected size ${leaf_hash.length}, want ${this.HASH_SIZE}`)
        }

        const [inner, border] = this.decompose_inclusion_proof(index, size)

        if (proof.length !== inner + border) {
            throw new Error(`Wrong proof size ${proof.length}, want ${inner + border}`)
        }

        let result = this.chain_inner(leaf_hash, proof.slice(0, inner), index)
        result = this.chain_border_right(result, proof.slice(inner, proof.length))
        return result
    }

    /**
     * Decompose inclusion proof into inner and border parts
     */
    private static decompose_inclusion_proof(index: number, size: number): [number, number] {
        const inner = this.inner_proof_size(index, size)
        const border = this.ones_count_64(index >> inner)
        return [inner, border]
    }

    /**
     * Calculate inner proof size
     */
    private static inner_proof_size(index: number, size: number): number {
        return this.length_64(index ^ (size - 1))
    }

    /**
     * Chain inner proof elements
     */
    private static chain_inner(
        seed: Uint8Array,
        proof: Uint8Array[],
        index: number
    ): Uint8Array {
        let result = seed
        for (let i = 0; i < proof.length; i++) {
            const h = proof[i]
            if ((index >> i) === 0) {
                result = this.hash_children(result, h)
            } else {
                result = this.hash_children(h, result)
            }
        }
        return result
    }

    /**
     * Chain border proof elements (right side)
     */
    private static chain_border_right(
        seed: Uint8Array,
        proof: Uint8Array[]
    ): Uint8Array {
        let result = seed
        for (const h of proof) {
            result = this.hash_children(h, result)
        }
        return result
    }

    /**
     * Hash two children nodes
     */
    private static hash_children(left: Uint8Array, right: Uint8Array): Uint8Array {
        const hasher = crypto.createHash('sha256')
        hasher.update(left)
        hasher.update(right)
        return hasher.digest()
    }

    /**
     * Count trailing zeros in 64-bit number
     */
    private static trailing_zeros_64(n: number): number {
        const ns = n.toString(2)
        let count = 0
        for (let i = ns.length - 1; i >= 0; i--) {
            if (ns[i] === '0') {
                count++
            } else {
                break
            }
        }
        return count
    }

    /**
     * Get length of binary representation
     */
    private static length_64(num: number): number {
        return num.toString(2).length
    }

    /**
     * Count ones in 64-bit number
     */
    private static ones_count_64(x: number): number {
        return (x.toString(2).match(/1/g) || []).length
    }

    /**
     * Compare two hashes
     */
    private static compare_hashes(hash1: Uint8Array, hash2: Uint8Array): boolean {
        if (hash1.length !== hash2.length) {
            return false
        }
        for (let i = 0; i < hash1.length; i++) {
            if (hash1[i] !== hash2[i]) {
                return false
            }
        }
        return true
    }
} 