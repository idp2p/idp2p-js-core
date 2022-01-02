import { ED25519, utils } from ".";
import { EventLog, EventLogPayload, EventLogSetDocument } from "./event_log";
import { MicroLedger, MicroLedgerInception, MicroLedgerState } from "./microledger";
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
    await createMicroLedger({ type: "Ok" });
});

test('verify invalid id test', async () => {
    try {
        await createMicroLedger({ type: "InvalidId" });
    } catch (e) {
        expect((e as Error).message).toBe("InvalidId");
    }
});

test('verify invalid previous test', async () => {
    try {
        await createMicroLedger({ type: "InvalidPrevious" });
    } catch (e) {
        expect((e as Error).message).toEqual("InvalidPrevious");
    }
});

test('verify invalid signature test', async () => {
    try {
        await createMicroLedger({ type: "InvalidEventSignature" });
    } catch (e) {
        expect((e as Error).message).toEqual("InvalidEventSignature");
    }
});

test('verify invalid signer test', async () => {
    try {
        await createMicroLedger({ type: "InvalidSigner" });
    } catch (e) {
        expect((e as Error).message).toEqual("InvalidSigner");
    }
});

async function createMicroLedger(testOptions: any): Promise<MicroLedgerState> {
    const secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.keyType = ED25519;
    inception.nextKeyDigest = await utils.secretToKeyDigest(secret);
    inception.recoveryKeyDigest = await utils.secretToKeyDigest(secret);
    let ledger = new MicroLedger();
    ledger.inception = inception;
    let change = new EventLogSetDocument();
    change.value = testOptions.docVal;
    let id = await inception.getId();
    const payload: EventLogPayload = {
        previous: testOptions.type === "InvalidPrevious" ? "1" : id,
        signerKey: utils.secretToEdPublic(secret),
        nextKeyDigest: inception.nextKeyDigest,
        change: change
    };
    let log = new EventLog();
    log.payload = payload;
    log.proof = testOptions.type === "InvalidEventSignature"
        ? "bafsf" : await utils.sign(payload, secret);
    ledger.events = [log];
    return await ledger.verify(testOptions.type === "InvalidId" ? "1" : id);
}