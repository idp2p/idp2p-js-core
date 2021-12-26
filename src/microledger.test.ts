import { ED25519, utils } from ".";
import { MicroLedgerInception } from "./microledger";
test('microledger inception test', async () => {
    const expectedId = "bagaaieravphdumkejbohc7auy7c5od6dm6t2kw6ljhsoml3aoarzbhxxzeea";
    const secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.keyType = ED25519;
    inception.nextKeyDigest = await utils.secretToKeyDigest(secret);
    inception.recoveryKeyDigest = await utils.secretToKeyDigest(secret);
    expect(await inception.getId()).toEqual(expectedId);
});