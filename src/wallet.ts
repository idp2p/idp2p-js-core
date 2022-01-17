import { AESKW } from "@stablelib/aes-kw";
import { RandomSource } from "@stablelib/random";
import { plainToInstance } from "class-transformer";
import { utils } from ".";
import { CreateIdentityInput, Identity } from "./did";
import { CreateDocInput, IdDocument } from "./did_doc";
const aesjs = require('aes-js');

export interface WalletStore {
    get(): Wallet;
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
    claims: IdentityClaim[] = [];
}

export class CreateWalletInput {
    id: string;
    password: string;
    providerUri: string;
    providerSecret: string;
}

export class Account {
    name: string;
    useSameKey: boolean;
    did: Identity;
    content: string;
}

export class Wallet {
    id: string; // unique identifier
    pwdKeySalt: string;
    wrappedKey: string;
    storage?: string; // if has a provider = uri, not = local
    accounts: Account[] = [];
    private getEncKey(password: string): Uint8Array | undefined {
        try {
            const pwdKey = utils.deriveKey(password, utils.decode(this.pwdKeySalt));
            const wrapper = new AESKW(pwdKey);
            return wrapper.unwrapKey(utils.decode(this.wrappedKey));
        } catch {
            return undefined;
        }
    }
    login(password: string): boolean {
        const result = this.getEncKey(password);
        return result !== undefined;
    }
    encrypt(password: string, secrets: WalletSecret): string {
        const key = this.getEncKey(password);
        const aesCtr = new aesjs.ModeOfOperation.ctr(key);
        const bytes = utils.toBytes(JSON.stringify(secrets));
        return utils.toString(aesCtr.encrypt(bytes));
    }
    decrypt(password: string, encryptedContent: string): WalletSecret {
        const key = this.getEncKey(password);
        const aesCtr = new aesjs.ModeOfOperation.ctr(key);
        const encryptedContentBytes = utils.toBytes(encryptedContent);
        const decrypted = utils.toString(aesCtr.decrypt(encryptedContentBytes));
        return plainToInstance(WalletSecret, JSON.parse(decrypted));
    }
}

export class WalletService {
    private prng: RandomSource;
    private store: WalletStore;

    constructor(prng: RandomSource, store: WalletStore) {
        this.prng = prng;
        this.store = store;
    }

    createWallet(id: string, password: string, storage?: string) {
        const encKey = this.prng.randomBytes(32);
        const salt = this.prng.randomBytes(16);
        const key = utils.deriveKey(password, salt);
        const wrapper = new AESKW(key);
        let wallet = new Wallet();
        wallet.storage = storage;
        wallet.id = id;
        wallet.wrappedKey = utils.encode(wrapper.wrapKey(encKey));
        wallet.pwdKeySalt = utils.encode(salt);
        this.store.save(wallet);
    }

    createAccount(name: string, password: string, claims: IdentityClaim[]) {
        let wallet = this.store.get();
        const inceptionSecret = this.prng.randomBytes(32);
        const nextSecret = this.prng.randomBytes(32);
        const recoverySecret = this.prng.randomBytes(32);
        const authenticationSecret = this.prng.randomBytes(32);
        const assertionSecret = this.prng.randomBytes(32);
        const agreementSecret = this.prng.randomBytes(32);
        let idInput = new CreateIdentityInput();
        idInput.nextKeyDigest = utils.secretToKeyDigest(inceptionSecret);
        idInput.recoveryKeyDigest = utils.secretToKeyDigest(recoverySecret);
        const did = Identity.new(idInput);
        let docInput = new CreateDocInput();
        docInput.id = did.id;
        docInput.assertionKey = utils.secretToEdPublic(assertionSecret);
        docInput.authenticationKey = utils.secretToEdPublic(authenticationSecret);
        docInput.agreementKey = utils.secretToEdPublic(agreementSecret);
        const doc = IdDocument.from(docInput);
        did.setDocument(inceptionSecret, utils.secretToKeyDigest(nextSecret), doc);
        let secret: IdentitySecret = {
            nextSecret: utils.encode(nextSecret),
            recoverySecret: utils.encode(recoverySecret),
            assertionSecret: utils.encode(assertionSecret),
            authenticationSecret: utils.encode(authenticationSecret),
            agreementSecret: utils.encode(agreementSecret),
        };
        let account = new Account();
        account.did = did;
        account.name = name;
        account.content = wallet.encrypt(password, { identitySecret: secret, claims: claims });
        wallet.accounts.push(account);
        this.store.save(wallet);
    }
}
















/*createDocument(username: string, password: string, did: Identity, service: Service[]) {
        let wallet = this.store.get();
        let secrets = wallet.decrypt(password, wallet.);
        const nextSecret = this.prng.randomBytes(256);
        const authenticationSecret = this.prng.randomBytes(256);
        const assertionSecret = this.prng.randomBytes(256);
        const agreementSecret = this.prng.randomBytes(256);
        let docInput = new CreateDocInput();
        docInput.assertionKey = utils.secretToEdPublic(assertionSecret);
        docInput.authenticationKey = utils.secretToEdPublic(authenticationSecret);
        docInput.agreementKey = utils.secretToEdPublic(agreementSecret);
        docInput.id = did.id;
        docInput.service = service;
        const doc = IdDocument.from(docInput);
        const signerSecret = utils.decode(secrets.identitySecret.nextSecret);
        did.setDocument(signerSecret, utils.secretToKeyDigest(nextSecret), doc);
        const identitySecret = {
            ...secrets.identitySecret,
            nextSecret: utils.encode(nextSecret),
            assertionSecret: utils.encode(assertionSecret),
            authenticationSecret: utils.encode(authenticationSecret),
            agreementSecret: utils.encode(agreementSecret)
        };
        wallet.encrypt(password, { ...secrets, identitySecret: identitySecret });
    }*/
/*importWallet(password: string, wallet: Wallet) {
    const salt = this.prng.randomBytes(128);
    const _encrypted = deriveKey(SHA256, utils.decode(password), salt, 128, 256);
    this.store.save(wallet);
}*/
/*recover(username: string, password: string, did: Identity) {
    let wallet = this.store.get(username);
    let secrets = wallet.decrypt(password);
    //did.microledger.saveEvent();
}*/