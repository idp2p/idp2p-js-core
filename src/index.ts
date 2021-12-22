import { CID } from 'multiformats/cid';
import { sha256 as hasher } from 'multiformats/hashes/sha2';
import { generateKeyPairFromSeed as generateAgreementKey } from "@stablelib/x25519";
import { generateKeyPairFromSeed as generateSignerKey, sign, verify } from "@stablelib/ed25519";
import { base32 } from "multiformats/bases/base32";
export const ED25519 = "Ed25519VerificationKey2020";
export const X25519 = "X25519KeyAgreementKey2020";

export class NextKey {
    type: string;
    value: string;
    static async from(secret: string):  Promise<NextKey>{
        let key = new NextKey();
        key.type = ED25519;
        key.value = await utils.secretToEdPublicDigest(secret);
        return key;
    }
}

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
    async secretToEdPublicDigest(base32Secret: string): Promise<string> {
        const keyPair = generateSignerKey(this.decode(base32Secret));
        const hash = await hasher.encode(keyPair.publicKey);
        return this.encode(hash);
    },
    secretToXPublic(base32Secret: string): string {
        const keyPair = generateAgreementKey(this.decode(base32Secret));
        return this.encode(keyPair.publicKey);
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
        const digest = await hasher.encode(bytes);
        var signature = sign(key.secretKey, digest);
        return this.encode(signature);
    },
    async verify(proof: string, data: any, publicKey: string) : Promise<Boolean> {
        const json = JSON.stringify(data);
        let bytes = Uint8Array.from(json, x => x.charCodeAt(0));
        const digest = await hasher.encode(bytes);
        return verify(this.decode(publicKey), digest, this.decode(proof));
    } 
}