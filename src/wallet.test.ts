import { defaultRandomSource } from "@stablelib/random";
import { Wallet, AccountContent, WalletService, WalletStore } from "./wallet";

class TestWalletStore implements WalletStore {
    private wallet!: Wallet;
    async get(): Promise<Wallet> {
        return this.wallet;
    }
    async save(wallet: Wallet) {
        this.wallet = wallet;
    }

}
test('wallet test', async () => {
    let store = new TestWalletStore();
    let walletService = new WalletService(defaultRandomSource, store);
    walletService.createWallet("123456");
    let secrets = new AccountContent();
    secrets.claims.push({ name: "key", value: "value" });
    const wallet = await store.get();
    let encrypted = wallet.encrypt("123456", secrets);
    const s = wallet.decrypt("123456", encrypted);
    expect(s.claims[0].name).toBe("key");
});

test('wallet service test', async () => {
    let store = new TestWalletStore();
    let walletService = new WalletService(defaultRandomSource, store);
    walletService.createWallet("123456");
    walletService.createAccount("ademcaglin", "123456", [{ name: "name", value: "value" }]);
    const wallet = await store.get();
    const content = wallet.decrypt("123456", wallet.accounts[0].encryptedContent);
    expect(content.identitySecret.agreementSecret).toBeTruthy();
});