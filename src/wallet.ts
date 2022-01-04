import { deriveKey } from "@stablelib/pbkdf2";
import { RandomSource } from "@stablelib/random";
import { SHA256 } from "@stablelib/sha256";
import { utils } from ".";
import { CreateIdentityInput, Identity } from "./did";
import { CreateDocInput, IdDocument, Service } from "./did_doc";
import { EventLogSetProof } from "./event_log";

export class IdentitySecret {
    nextSecret: string;
    recoverySecret: string;
    assertionSecret: string;
    authenticationSecret: string;
    agreementSecret: string;
}

export class WalletContent {
    identitySecret: IdentitySecret;
    credentials: any[];
}

export class WalletOptions {
    useSameKey: boolean;
    prng: RandomSource;
}

export class Wallet {
    private prng: RandomSource;
    name: string;
    useSameKey: boolean;
    keySalt: string;
    keyDigest: string;
    did: Identity;
    content: string;

    constructor(options: WalletOptions) {
        this.useSameKey = options.useSameKey;
        this.prng = options.prng;
    }

    private resolve(password: string): WalletContent {
        let content = new WalletContent();
        return content;
    }

    private save(password: string, content: WalletContent) {

        // encrypt
    }

    createIdentity(password: string, service: Service[]) {
        const inceptionSecret = this.prng.randomBytes(256);
        const nextSecret = this.prng.randomBytes(256);
        const recoverySecret = this.prng.randomBytes(256);
        const authenticationSecret = this.prng.randomBytes(256);
        const assertionSecret = this.prng.randomBytes(256);
        const agreementSecret = this.prng.randomBytes(256);
        let idInput = new CreateIdentityInput();
        idInput.nextKeyDigest = utils.secretToKeyDigest(inceptionSecret);
        idInput.recoveryKeyDigest = utils.secretToKeyDigest(recoverySecret);
        const did = Identity.new(idInput);
        let docInput = new CreateDocInput();
        docInput.assertionKey = utils.secretToEdPublic(assertionSecret);
        docInput.authenticationKey = utils.secretToEdPublic(authenticationSecret);
        docInput.agreementKey = utils.secretToEdPublic(agreementSecret);
        docInput.id = did.id;
        docInput.service = service;
        const doc = IdDocument.from(docInput);
        did.setDocument(inceptionSecret, utils.secretToKeyDigest(nextSecret), doc);
        let secret: IdentitySecret = {
            nextSecret: utils.encode(nextSecret),
            recoverySecret: utils.encode(recoverySecret),
            assertionSecret: utils.encode(assertionSecret),
            authenticationSecret: utils.encode(authenticationSecret),
            agreementSecret: utils.encode(agreementSecret),
        };
        this.did = did;
        let content = this.resolve(password);
        content.identitySecret = secret;
        this.save(password, content);
    }

    createDocument(password: string, service: Service[]) {
        let content = this.resolve(password);
        const nextSecret = this.prng.randomBytes(256);
        const authenticationSecret = this.prng.randomBytes(256);
        const assertionSecret = this.prng.randomBytes(256);
        const agreementSecret = this.prng.randomBytes(256);
        let docInput = new CreateDocInput();
        docInput.assertionKey = utils.secretToEdPublic(assertionSecret);
        docInput.authenticationKey = utils.secretToEdPublic(authenticationSecret);
        docInput.agreementKey = utils.secretToEdPublic(agreementSecret);
        docInput.id = this.did.id;
        docInput.service = service;
        const doc = IdDocument.from(docInput);
        const signerSecret = utils.decode(content.identitySecret.nextSecret);
        this.did.setDocument(signerSecret, utils.secretToKeyDigest(nextSecret), doc);
        content.identitySecret = { ...content.identitySecret, };
        this.save(password, content);
    }

    createCredential(password: string, credentials: any[]) {
        let content = this.resolve(password);
        const nextSecretDigest = utils.secretToKeyDigest(this.prng.randomBytes(256));
        const signerSecret = utils.decode(content.identitySecret.nextSecret);
        for (const credential of credentials){
            content.credentials.push(credential);
        }

        const change = new EventLogSetProof();

        this.did.microledger.saveEvent(signerSecret, nextSecretDigest, change);
        content.identitySecret = { ...content.identitySecret, };
        this.save(password, content);
    }

    recover(password: string) {
        let content = this.resolve(password);
        this.save(password, content);
    }

    publish(url: string) {

    }

    static new(name: string, password: string, prng: RandomSource): Wallet {
        const salt = prng.randomBytes(128);
        const encrypted = deriveKey(SHA256, utils.decode(password), salt, 128, 256);
        let wallet = new Wallet({ useSameKey: true, prng: prng });
        wallet.name = name;
        wallet.keyDigest = utils.encode(encrypted);
        wallet.keySalt = utils.encode(salt);
        return wallet;
    }

    static import(password: string, content: string, prng: RandomSource): Wallet {
        return new Wallet({ useSameKey: true, prng: prng });
    }
}
