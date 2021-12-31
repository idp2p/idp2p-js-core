import { utils } from ".";
import { EventLog, EventLogPayload, EventLogSetDocument } from "./event_log";

test('did_doc parse', async () => {
    const secret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
    let log = new EventLog();
    let payload = new EventLogPayload();
    let change = new EventLogSetDocument();
    change.value = "b";
    payload.previous = "1";
    payload.signerKey = "brgzkmbdnyevdth3sczvxjumd6bdl6ngn6eqbsbpazuvq42bfzk2a";
    payload.nextKeyDigest = "bcodiqdow4rvnu4o2wwtpv6dvjjsd63najdeazekh4w3s2dyb2tvq";
    payload.change = change;
    log.payload = payload;
    log.proof = await utils.sign(payload, secret);
    const expected = {
        payload: {
            previous: "1",
            signerKey: "brgzkmbdnyevdth3sczvxjumd6bdl6ngn6eqbsbpazuvq42bfzk2a",
            nextKeyDigest: "bcodiqdow4rvnu4o2wwtpv6dvjjsd63najdeazekh4w3s2dyb2tvq",
            change: { type: "SetDocument", value: "b" }
        },
        proof: "b5hpli3wz7repyggufuhwwhej6ql5tjruh6d5kljld4rgnxet5g2jswetzguru6c2wne5kdeq5q5jx72l57jwrqcf6fcxu5bizqgh4cq"
    };
    let verified = await utils.verify(log.proof, payload, payload.signerKey);
    expect(verified).toBeTruthy();
    expect(JSON.stringify(log)).toEqual(JSON.stringify(expected));
});