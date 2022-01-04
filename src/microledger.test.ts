import { ED25519, utils } from ".";
import { EventLog, EventLogPayload, EventLogSetDocument } from "./event_log";
import { MicroLedger, MicroLedgerInception, MicroLedgerState } from "./microledger";
test('id test', () => {
    const secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    const expectedId = "bagaaieravphdumkejbohc7auy7c5od6dm6t2kw6ljhsoml3aoarzbhxxzeea";
    let inception = new MicroLedgerInception();
    inception.keyType = ED25519;
    inception.nextKeyDigest = utils.encode(utils.secretToKeyDigest(utils.decode(secret)));
    inception.recoveryKeyDigest = utils.encode(utils.secretToKeyDigest(utils.decode(secret)));
    expect(inception.getId()).toEqual(expectedId);
});

test('verify test', () => {
    createMicroLedger({ type: "Ok" });
});

test('verify invalid id test', () => {
    try {
        createMicroLedger({ type: "InvalidId" });
    } catch (e) {
        expect((e as Error).message).toBe("InvalidId");
    }
});

test('verify invalid previous test', () => {
    try {
        createMicroLedger({ type: "InvalidPrevious" });
    } catch (e) {
        expect((e as Error).message).toEqual("InvalidPrevious");
    }
});

test('verify invalid signature test', () => {
    try {
        createMicroLedger({ type: "InvalidEventSignature" });
    } catch (e) {
        expect((e as Error).message).toEqual("InvalidEventSignature");
    }
});

test('verify invalid signer test', () => {
    try {
        createMicroLedger({ type: "InvalidSigner" });
    } catch (e) {
        expect((e as Error).message).toEqual("InvalidSigner");
    }
});

function createMicroLedger(testOptions: any): MicroLedgerState {
    const secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    let inception = new MicroLedgerInception();
    inception.keyType = ED25519;
    inception.nextKeyDigest = utils.encode(utils.secretToKeyDigest(utils.decode(secret)));
    inception.recoveryKeyDigest = utils.encode(utils.secretToKeyDigest(utils.decode(secret)));
    let ledger = new MicroLedger();
    ledger.inception = inception;
    let change = new EventLogSetDocument();
    change.value = testOptions.docVal;
    let id = inception.getId();
    const payload: EventLogPayload = {
        previous: testOptions.type === "InvalidPrevious" ? "1" : id,
        signerKey: utils.encode(utils.secretToEdPublic(utils.decode(secret))),
        nextKeyDigest: inception.nextKeyDigest,
        change: change
    };
    let log = new EventLog();
    log.payload = payload;
    const proof = utils.sign(payload, utils.decode(secret));
    let wrong_proof = new Uint8Array(256);
    log.proof = testOptions.type === "InvalidEventSignature" ? utils.encode(wrong_proof) : utils.encode(proof);
    ledger.events = [log];
    return ledger.verify(testOptions.type === "InvalidId" ? "1" : id);
}