import {MicroLedgerInception} from "./microledger";
import {SignerKey, RecoveryKey} from "./main";
test('microledger inception test', async () => {
    const expected_id = "bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja";
    const signed_secret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
    const recovery_secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.signer_key = SignerKey.from(signed_secret);
    inception.recovery_key = await RecoveryKey.from(recovery_secret);
    console.log(inception);
    expect(await inception.getId()).toEqual(expected_id);
});