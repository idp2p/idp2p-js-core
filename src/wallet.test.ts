import { defaultRandomSource } from "@stablelib/random";
import { CreateWalletInput, Wallet, WalletSecret, WalletService, WalletStore } from "./wallet";

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
    walletService.createWallet("ademcaglin","123456");
    let secrets = new WalletSecret();
    secrets.claims.push({ name: "key", value: "value" });
    const wallet =store.get();
    let encrypted = wallet.encrypt("123456", secrets);
    const s = wallet.decrypt("123456", encrypted);
    expect(s.claims[0].name).toBe("key");
});

test('wallet service test', () => {
    let store = new TestWalletStore();
    let walletService = new WalletService(defaultRandomSource, store);
    let input = new CreateWalletInput();
    input.id = "ademcaglin";
    input.password = "123456";
    input.providerUri = "http://localhost:3000";
    input.providerSecret = "123456";
    walletService.createWallet("ademcaglin", "123456");
    walletService.createAccount("ademcaglin", "123456", [{ name: "name", value: "value" }]);
    //let wallet = store.get();
    //console.log(JSON.stringify(instanceToPlain(wallet.accounts[0].did.document)));
});