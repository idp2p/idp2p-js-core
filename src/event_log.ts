export class EventLogRecover {
    type: string = "Recover";
    keyType: string;
    recoveryKeyDigest: string;
}

export class EventLogSetProof {
    type: string = "SetSetProof";
    key: string;
    value: string;
}

export class EventLogSetDocument {
    type: string = "SetDocument";
    value: string;
}

export class EventLogPayload {
    previous: string;
    signerKey: string;
    nextKeyDigest: string;
    change: EventLogRecover | EventLogSetProof | EventLogSetDocument;
}

export class EventLog {
    payload: EventLogPayload;
    proof: string;
}
