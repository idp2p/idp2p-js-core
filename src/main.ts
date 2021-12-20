import { CID } from 'multiformats/cid';
import { sha256 as hasher } from 'multiformats/hashes/sha2';
import { generateKeyPairFromSeed } from "@stablelib/x25519";
import { base32 } from "multiformats/bases/base32";
const EdDSA = require('elliptic').eddsa;
export const ED25519 = "Ed25519VerificationKey2020";
export const X25519 = "X25519KeyAgreementKey2020";

export class SignerKey {
    type: string;
    public: string;

    static from(secret: string) : SignerKey{
        let key = new SignerKey();
        key.type = ED25519;
        key.public = utils.secretToEdPublic(secret);
        return key;
    }
}

export class RecoveryKey {
    type: string;
    digest: string;
    static async from(secret: string):  Promise<RecoveryKey>{
        let key = new RecoveryKey();
        key.type = ED25519;
        key.digest = await utils.secretToEdPublicDigest(secret);
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
        let ec = new EdDSA('ed25519');
        const key = ec.keyFromSecret(this.decode(base32Secret));
        const publicKey = this.encode(new Uint8Array(key.getPublic()));
        return publicKey;
    },
    async secretToEdPublicDigest(base32Secret: string): Promise<string> {
        let ec = new EdDSA('ed25519');
        const key = ec.keyFromSecret(this.decode(base32Secret));
        const publicKey = new Uint8Array(key.getPublic());
        const hash = await hasher.encode(publicKey);
        return this.encode(hash);
    },
    secretToXPublic(base32Secret: string): string {
        const keyPair = generateKeyPairFromSeed(this.decode(base32Secret));
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
}