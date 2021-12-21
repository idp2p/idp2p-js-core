import {MicroLedgerInception} from "./microledger";
import {IdKey} from "./main";
test('microledger inception test', async () => {
    const expectedId = "bagaaieraertv7otpqyboblocnnzel7k5ssjysaj2twc2sxjataa6hsa4ouwa";
    const signedSecret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
    const recoverySecret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.signerKey = await IdKey.from(signedSecret);
    inception.recoveryKey = await IdKey.from(recoverySecret);
    console.log(inception);
    expect(await inception.getId()).toEqual(expectedId);
});