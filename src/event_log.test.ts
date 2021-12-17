import {  instanceToPlain, plainToInstance } from "class-transformer";
import {EventLog, EventLogPayload, EventLogSetProofChange} from "./event_log";

test('did_doc parse', () => {
    let e = new EventLog();
    let p = new EventLogPayload();
    let c = new EventLogSetProofChange();
    c.type = "set_proof";
    c.key = "1";
    c.value = "2";
    p.change = c;
    p.signer_public = "signer_public";
    p.previous = "1";
    e.payload = p;
    e.proof = "proof";
    let plain = instanceToPlain(e);
    console.log(plainToInstance(EventLogPayload, plain));
    console.log(JSON.stringify(plain));
    //expect(doc.id).toBe("did:p2p:bagaaieratxin");
});