import { utils } from ".";
import {MicroLedgerInception} from "./microledger";
test('microledger inception test', async () => {
    const expectedId = "bagaaieraa3osn7ivjmkipdjluomerepr4hs7c647rux3mh5tkamaelgoycjq";
    const recoverySecret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    const inceptionSecret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.inceptionPublicKey = await utils.getDigest(inceptionSecret);
    inception.recoveryNextKeyDigest = await utils.getDigest(recoverySecret);
    console.log(inception);
    expect(await inception.getId()).toEqual(expectedId);
});