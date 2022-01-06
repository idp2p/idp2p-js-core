import { deriveKey } from "@stablelib/pbkdf2";
import { RandomSource } from "@stablelib/random";
import { SHA256 } from "@stablelib/sha256";
import { utils } from ".";
import { CreateIdentityInput, Identity } from "./did";
import { CreateDocInput, IdDocument, Service } from "./did_doc";

export interface WalletStore {
    get(name: string): Wallet;
    save(wallet: Wallet): void;
}

export class IdentitySecret {
    nextSecret: string;
    recoverySecret: string;
    assertionSecret: string;
    authenticationSecret: string;
    agreementSecret: string;
}

export class IdentityClaim {
    name: string;
    value: string;
}

export class WalletSecret {
    identitySecret: IdentitySecret;
    claims: IdentityClaim[];
}

export class CreateWalletInput {
    name: string;
    password: string;
    useSameKey: boolean = true;
    providerUri: string;
    providerSecret: string;
}

export class Wallet {
    name: string;
    useSameKey: boolean;
    useNativeProvider: boolean;
    providerUri: string;
    providerSecret: string;
    keySalt: string;
    keyDigest: string;
    did: Identity;
    secret: string;// encrypted
}

export class WalletService {
    private prng: RandomSource;
    private store: WalletStore;

    constructor(prng: RandomSource, store: WalletStore) {
        this.prng = prng;
        this.store = store;
    }

    createWallet(input: CreateWalletInput) {
        let wallet = new Wallet();
        const salt = this.prng.randomBytes(128);
        const encrypted = deriveKey(SHA256, utils.decode(input.password), salt, 128, 256);
        wallet.name = input.name;
        wallet.keyDigest = utils.encode(encrypted);
        wallet.keySalt = utils.encode(salt);
        wallet.useSameKey = input.useSameKey;
        wallet.providerUri = input.providerUri;
        wallet.providerSecret = input.providerSecret;
        this.store.save(wallet);
    }

    importWallet(password: string, wallet: Wallet) {
        const salt = this.prng.randomBytes(128);
        const _encrypted = deriveKey(SHA256, utils.decode(password), salt, 128, 256);
        this.store.save(wallet);
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

    createClaim(password: string, claims: IdentityClaim[]) {
        let content = this.resolve(password);
        for (const claim of claims) {
            content.claims.push(claim);
        }
        content.identitySecret = { ...content.identitySecret, };
        this.save(password, content);
    }

    recover(password: string) {
        let content = this.resolve(password);
        this.save(password, content);
    }

    private resolve(password: string): WalletSecret {
        let content = new WalletSecret();
        const _key = deriveKey(SHA256, utils.decode(password), utils.decode(this.keySalt), 128, 256);
        return content;
    }

    private save(password: string, content: WalletSecret) {

        // encrypt
    }
}
