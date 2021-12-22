import {MicroLedgerInception} from "./microledger";
import {NextKey} from ".";
test('microledger inception test', async () => {
    const expectedId = "bagaaiera5ce3nckdmy5yd2hwzfpmcwnd2pldaqgbstgdrilhwaoanpzwsofa";
    const signedSecret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
    const recoverySecret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.signerNextKey = await NextKey.from(signedSecret);
    inception.recoveryNextKey = await NextKey.from(recoverySecret);
    console.log(inception);
    expect(await inception.getId()).toEqual(expectedId);
});