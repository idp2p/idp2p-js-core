import { ED25519, utils } from ".";

export type EventLogChange = EventLogRecover | EventLogSetProof | EventLogSetDocument;

export class EventLogRecover {
    type: string;
    keyType: string;
    recoveryKeyDigest: string;
    constructor(recoveryKeyDigest: string) {
      this.type = "Recover";
      this.keyType = ED25519;
      this.recoveryKeyDigest = recoveryKeyDigest;
    }
}

export class EventLogSetProof {
    type: string ;
    key: string;
    value: string;
    constructor( key: string, value: string) {
        this.type = "SetSetProof";
        this.key = key;
        this.value = value;
    }
}

export class EventLogSetDocument {
    type: string;
    value: string;
    constructor(value: string) {
        this.type = "SetDocument";
        this.value = value;
    }
}

export class EventLogPayload {
    previous: string;
    signerKey: string;
    nextKeyDigest: string;
    change: EventLogChange;
    timestamp: number;
    constructor(previous: string, signerKey: string, nextKeyDigest: string, change: EventLogChange, timestamp: number){
        this.previous = previous;
        this.signerKey = signerKey;
        this.nextKeyDigest = nextKeyDigest;
        this.change = change;
        this.timestamp = timestamp;
    }
}

export class EventLog {
    payload: EventLogPayload;
    proof: string;
    constructor(payload: EventLogPayload, proof: string) {
        this.payload = payload;
        this.proof = proof;
    }
    getId(): string{
        return utils.getCid(this);
    }
}
