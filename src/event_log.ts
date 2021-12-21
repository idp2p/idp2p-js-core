import { IdKey } from "./main";

export class EventLogRecoverChange {
    nextRecoveryKey: IdKey;
}

export class EventLogSetProofChange {
    key: string;
    value: string;
}

export class EventLogSetDocChange {
    value: string;
}

export class EventLogPayload {
    previous: string;
    type: string;
    signerPublic: string;
    nextSignerKey: IdKey;
    change: EventLogRecoverChange | EventLogSetProofChange | EventLogRecoverChange;
}

export class EventLog {
    payload: EventLogPayload;
    proof: string;
}
