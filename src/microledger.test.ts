import { ED25519, utils } from ".";
import { MicroLedger, MicroLedgerInception } from "./microledger";
test('id test', async () => {
    const secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    const expectedId = "bagaaieravphdumkejbohc7auy7c5od6dm6t2kw6ljhsoml3aoarzbhxxzeea";
    let inception = new MicroLedgerInception();
    inception.keyType = ED25519;
    inception.nextKeyDigest = await utils.secretToKeyDigest(secret);
    inception.recoveryKeyDigest = await utils.secretToKeyDigest(secret);
    expect(await inception.getId()).toEqual(expectedId);
});

test('verify test', async () => {
    const secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.keyType = ED25519;
    inception.nextKeyDigest = await utils.secretToKeyDigest(secret);
    inception.recoveryKeyDigest = await utils.secretToKeyDigest(secret);
    let ledger = new MicroLedger();
    ledger.inception = inception;
    const result = await ledger.verify(await ledger.inception.getId());
    expect(result.nextKeyDigest).toEqual(inception.nextKeyDigest);
});

test('verify invalid id test', async () => {
    try{
        const secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
        let inception = new MicroLedgerInception();
        inception.keyType = ED25519;
        inception.nextKeyDigest = await utils.secretToKeyDigest(secret);
        inception.recoveryKeyDigest = await utils.secretToKeyDigest(secret);
        let ledger = new MicroLedger();
        ledger.inception = inception;
        let wrongId = "baa";
        await ledger.verify(wrongId);
    }catch(e){
        expect((e as Error).message).toBe("InvalidId");
    }
});

/**
 * let secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
        let next_key = to_verification_publickey(&multibase::decode(secret).unwrap().1);
        let recovery_key = to_verification_publickey(&multibase::decode(secret).unwrap().1);
        let ledger = MicroLedger::new(&next_key, &recovery_key);
        let id = format!("{}.", ledger.inception.get_id());
        let result = ledger.verify(&id);     
        let is_err = matches!(result, Err(crate::IdentityError::InvalidId));
        assert!(is_err, "{:?}", result);
 */