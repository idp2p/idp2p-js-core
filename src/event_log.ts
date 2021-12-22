import { NextKey } from "./main";

export class EventLogRecoverChange {
    type: string= "SetRecoveryKey";
    nextRecoveryKey: NextKey;
}

export class EventLogSetProofChange {
    type: string = "SetProof";
    key: string;
    value: string;
}

export class EventLogSetDocChange {
    type: string= "SetDocument";
    value: string;
}

export class EventLogPayload {
    previous: string;
    signerPublic: string;
    nextSignerKey: NextKey;
    change: EventLogRecoverChange | EventLogSetProofChange | EventLogRecoverChange;
}

export class EventLog {
    payload: EventLogPayload;
    proof: string;
}
