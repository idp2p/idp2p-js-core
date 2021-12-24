import { ED25519, utils } from ".";
import { MicroLedgerInception } from "./microledger";
test('microledger inception test', async () => {
    const expectedId = "bagaaieray3luw27xnz5ed3537eoihoztehssbyulwukju6eg6ltjmgtorzzq";
    const recoverySecret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    const inceptionSecret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.keyType = ED25519;
    inception.inceptionKey = utils.secretToEdPublic(inceptionSecret);
    inception.recoveryKeyDigest = await utils.secretToKeyDigest(recoverySecret);
    expect(await inception.getId()).toEqual(expectedId);
});