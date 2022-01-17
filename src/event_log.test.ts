import { utils } from ".";
import { EventLog, EventLogPayload, EventLogSetDocument } from "./event_log";

test('event log test', () => {
    const secret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
    const signerKey = "brgzkmbdnyevdth3sczvxjumd6bdl6ngn6eqbsbpazuvq42bfzk2a";
    const nextKeyDigest = "bcodiqdow4rvnu4o2wwtpv6dvjjsd63najdeazekh4w3s2dyb2tvq";
    let change = new EventLogSetDocument("b");  
    let payload = new EventLogPayload("1", signerKey, nextKeyDigest, change, 0);
    const proof = utils.encode(utils.sign(payload, utils.decode(secret)));
    let log = new EventLog(payload, proof);

    const expected = {
        payload: {
            previous: "1",
            signerKey: "brgzkmbdnyevdth3sczvxjumd6bdl6ngn6eqbsbpazuvq42bfzk2a",
            nextKeyDigest: "bcodiqdow4rvnu4o2wwtpv6dvjjsd63najdeazekh4w3s2dyb2tvq",
            change: { type: "SetDocument", value: "b" },
            timestamp: 0
        },
        proof: "bvxrlrdqsehngru6c3k77d3a4cye7jis3yakkvqanb4btvg3la5a2cqchfpjmyotqhm3mye5j4dp27w2nwdp3tskwjvpnza3y6udg6cq"
    };
    let verified = utils.verify(utils.decode(log.proof), payload, utils.decode(payload.signerKey));
    expect(verified).toBeTruthy();
    expect(JSON.stringify(log)).toEqual(JSON.stringify(expected));
});