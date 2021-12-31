import { CID } from 'multiformats/cid';
import { sha256 as hasher } from 'multiformats/hashes/sha2';
import { generateKeyPairFromSeed as generateAgreementKey } from "@stablelib/x25519";
import { generateKeyPairFromSeed as generateSignerKey, sign, verify } from "@stablelib/ed25519";
import { base32 } from "multiformats/bases/base32";
export const ED25519 = "Ed25519VerificationKey2020";
export const X25519 = "X25519KeyAgreementKey2020";

export const utils = {
    encode(bytes: Uint8Array): string {
        return base32.encode(bytes)
    },
    decode(str: string): Uint8Array {
        return base32.decode(str)
    },
    secretToEdPublic(base32Secret: string): string {
        const keyPair = generateSignerKey(this.decode(base32Secret));
        return this.encode(keyPair.publicKey);
    },
    secretToXPublic(base32Secret: string): string {
        const keyPair = generateAgreementKey(this.decode(base32Secret));
        return this.encode(keyPair.publicKey);
    },
    async secretToKeyDigest(base32Secret: string): Promise<string> {
        const keyPair = generateSignerKey(this.decode(base32Secret));
        const hash = await hasher.encode(keyPair.publicKey);
        return this.encode(hash);
    },
    async getCid(data: any): Promise<string> {
        let bytes = Uint8Array.from(JSON.stringify(data), x => x.charCodeAt(0));
        const hash = await hasher.digest(bytes);
        const cid = CID.create(1, 512, hash);
        return cid.toString();
    },
    async getDigest(data: any): Promise<string> {
        let bytes = Uint8Array.from(JSON.stringify(data), x => x.charCodeAt(0));
        const hash = await hasher.encode(bytes);
        return this.encode(hash);
    },
    async sign(data: any, secret: string): Promise<string>{
        const key = generateSignerKey(this.decode(secret));
        const json = JSON.stringify(data);
        let bytes = Uint8Array.from(json, x => x.charCodeAt(0));
        var signature = sign(key.secretKey, bytes);
        return this.encode(signature);
    },
    async verify(proof: string, data: any, publicKey: string) : Promise<Boolean> {
        const json = JSON.stringify(data);
        let bytes = Uint8Array.from(json, x => x.charCodeAt(0));
        return verify(this.decode(publicKey), bytes, this.decode(proof));
    } 
}