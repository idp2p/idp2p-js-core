import { AESKW } from "@stablelib/aes-kw";
import { RandomSource } from "@stablelib/random";
import { hash } from "@stablelib/sha256";
import { plainToInstance } from "class-transformer";
import { utils } from ".";
import { CreateIdentityInput, Identity } from "./did";
import { CreateDocInput, IdDocument } from "./did_doc";
const aesjs = require('aes-js');

export interface WalletStore {
    get(): Promise<Wallet>;
    save(wallet: Wallet): Promise<void>;
}

export class IdentitySecret {
    nextSecret: string;
    assertionSecret: string;
    authenticationSecret: string;
    agreementSecret: string;
}

export class IdentityClaim {
    name: string;
    value: string;
}

export class AccountContent {
    identitySecret: IdentitySecret;
    claims: IdentityClaim[] = [];
}

export class Account {
    name: string;
    identity: Identity;
    useSameKey: boolean;
    encryptedContent: string;
}

export class Wallet {
    masterKeySalt: string;
    wrappedEncKey: string;
    providerUri?: string; 
    accounts: Account[] = [];
    private getMasterKey(password: string): Uint8Array{
        return utils.deriveKey(password, utils.decode(this.masterKeySalt));
    }

    private getEncKey(password: string): Uint8Array | undefined {
        try {
            const pwdKey = this.getMasterKey(password);
            const wrapper = new AESKW(pwdKey);
            return wrapper.unwrapKey(utils.decode(this.wrappedEncKey));
        } catch {
            return undefined;
        }
    }

    login(password: string): boolean {
        const result = this.getEncKey(password);
        return result !== undefined;
    }
    encrypt(password: string, content: AccountContent): string {
        const key = this.getEncKey(password);
        const aesCtr = new aesjs.ModeOfOperation.ctr(key);
        const bytes = utils.toBytes(JSON.stringify(content));
        return utils.toString(aesCtr.encrypt(bytes));
    }
    decrypt(password: string, encryptedContent: string): AccountContent {
        const key = this.getEncKey(password);
        const aesCtr = new aesjs.ModeOfOperation.ctr(key);
        const encryptedContentBytes = utils.toBytes(encryptedContent);
        const decrypted = utils.toString(aesCtr.decrypt(encryptedContentBytes));
        return plainToInstance(AccountContent, JSON.parse(decrypted));
    }
    getId(password: string): string{
        const masterKey = this.getMasterKey(password);
        const secret = hash(masterKey);
        return utils.encode(utils.secretToEdPublic(secret));    
    }
}

export class WalletService {
    private prng: RandomSource;
    private store: WalletStore;

    constructor(prng: RandomSource, store: WalletStore) {
        this.prng = prng;
        this.store = store;
    }

    async createWallet(password: string, providerUri?: string): Promise<string> {
        const encKey = this.prng.randomBytes(32);
        const salt = this.prng.randomBytes(16);
        const key = utils.deriveKey(password, salt);
        const wrapper = new AESKW(key);
        let wallet = new Wallet();
        wallet.providerUri = providerUri;
        wallet.masterKeySalt = utils.encode(salt);
        wallet.wrappedEncKey = utils.encode(wrapper.wrapKey(encKey));
        await this.store.save(wallet);
        return utils.encode(salt);
    }

    async createAccount(name: string, password: string, claims: IdentityClaim[]): Promise<Uint8Array> {
        let wallet = await this.store.get();
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
            assertionSecret: utils.encode(assertionSecret),
            authenticationSecret: utils.encode(authenticationSecret),
            agreementSecret: utils.encode(agreementSecret),
        };
        let account = new Account();
        account.identity = did;
        account.name = name;
        account.encryptedContent = wallet.encrypt(password, { identitySecret: secret, claims: claims });
        wallet.accounts.push(account);
        await this.store.save(wallet);
        return recoverySecret;
    }
}


