import {MicroLedgerInception} from "./microledger";
import {NextKey} from "./main";
test('microledger inception test', async () => {
    const expectedId = "bagaaierawxm3nsobohk7ljdupuj5cc2u7h4dhbqfz7mp5o24qk7o2xhm6pmq";
    const signedSecret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
    const recoverySecret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.signerNextKey = await NextKey.from(signedSecret);
    inception.recoveryNextKey = await NextKey.from(recoverySecret);
    console.log(inception);
    expect(await inception.getId()).toEqual(expectedId);
});