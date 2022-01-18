import { defaultRandomSource } from "@stablelib/random";
import { Wallet, AccountContent, WalletService, WalletStore } from "./wallet";

class TestWalletStore implements WalletStore {
    private wallet: Wallet;
    get(): Wallet {
        return this.wallet;
    }
    save(wallet: Wallet): void {
        this.wallet = wallet;
    }

}
test('wallet test', () => {
    let store = new TestWalletStore();
    let walletService = new WalletService(defaultRandomSource, store);
    walletService.createWallet("123456");
    let secrets = new AccountContent();
    secrets.claims.push({ name: "key", value: "value" });
    const wallet =store.get();
    let encrypted = wallet.encrypt("123456", secrets);
    const s = wallet.decrypt("123456", encrypted);
    expect(s.claims[0].name).toBe("key");
});

test('wallet service test', () => {
    let store = new TestWalletStore();
    let walletService = new WalletService(defaultRandomSource, store);
    walletService.createWallet("123456");
    walletService.createAccount("ademcaglin", "123456", [{ name: "name", value: "value" }]);
    //const w = store.get();
    //console.log(w.decrypt("123456", w.accounts[0].encryptedContent));
});