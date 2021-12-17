export class EventLogRecoverChange{
    type: string;
}

export class EventLogSetProofChange{
    type: string;
    key: string;
    value: string;
}

export class EventLogSetDocChange {
    type: string;
    value: string;
}

export class EventLogPayload {
    previous: string;
    signer_public: string;
    change: EventLogRecoverChange | EventLogSetProofChange | EventLogSetDocChange;
}

export class EventLog {
    payload: EventLogPayload;
    proof: string;
}
