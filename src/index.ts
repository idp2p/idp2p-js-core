import { CID } from 'multiformats/cid';
import { generateKeyPairFromSeed as generateAgreementKey } from "@stablelib/x25519";
import { generateKeyPairFromSeed as generateSignerKey, sign, verify } from "@stablelib/ed25519";
import { base32 } from "multiformats/bases/base32";
import { hash } from '@stablelib/sha256';
import { create } from 'multiformats/hashes/digest';
export const ED25519 = "Ed25519VerificationKey2020";
export const X25519 = "X25519KeyAgreementKey2020";

export const utils = {
    encode(bytes: Uint8Array): string {
        return base32.encode(bytes)
    },
    decode(str: string): Uint8Array {
        return base32.decode(str)
    },
    secretToEdPublic(secret: Uint8Array): Uint8Array {
        const keyPair = generateSignerKey(secret);
        return keyPair.publicKey;
    },
    secretToXPublic(secret: Uint8Array): Uint8Array {
        const keyPair = generateAgreementKey(secret);
        return keyPair.publicKey;
    },
    secretToKeyDigest(secret: Uint8Array): Uint8Array {
        const keyPair = generateSignerKey(secret);
        return hash(keyPair.publicKey);
    },
    getCid(data: any): string {
        let bytes = Uint8Array.from(JSON.stringify(data), x => x.charCodeAt(0));
        const digest = create(18, hash(bytes))
        const cid = CID.create(1, 512, digest);
        return cid.toString();
    },
    getDigest(data: any): Uint8Array {
        let bytes = Uint8Array.from(JSON.stringify(data), x => x.charCodeAt(0));
        return hash(bytes);
    },
    sign(data: any, secret: Uint8Array): Uint8Array {
        const key = generateSignerKey(secret);
        const json = JSON.stringify(data);
        let bytes = Uint8Array.from(json, x => x.charCodeAt(0));
        var signature = sign(key.secretKey, bytes);
        return signature;
    },
    verify(proof: Uint8Array, data: any, publicKey: Uint8Array): Boolean {
        try {
            const json = JSON.stringify(data);
            let bytes = Uint8Array.from(json, x => x.charCodeAt(0));
            return verify(publicKey, bytes, proof);
        } catch {
            return false;
        }
    }
}