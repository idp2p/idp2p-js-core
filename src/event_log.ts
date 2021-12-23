export class EventLogSetRecoveryKeyChange {
    type: string = "SetRecoveryKey";
    recoveryNextKeyDigest: string;
}

export class EventLogSetProofChange {
    type: string = "SetSetProof";
    key: string;
    value: string;
}

export class EventLogSetDocumentChange {
    type: string = "SetDocument";
    value: string;
}

export class EventLogPayload {
    previous: string;
    signerPublicKey: string;
    signerNextKeyDigest: string;
    change: EventLogSetRecoveryKeyChange | EventLogSetProofChange | EventLogSetDocumentChange;
}

export class EventLog {
    payload: EventLogPayload;
    proof: string;
}
