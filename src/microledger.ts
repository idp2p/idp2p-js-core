import assert from "assert";
import { Type } from "class-transformer";
import {
    EventLog,
    EventLogChange,
    EventLogPayload,
    EventLogRecover,
    EventLogSetDocument,
    EventLogSetProof
} from "./event_log";
import { utils } from ".";
import { hash } from "@stablelib/sha256";

export class MicroLedgerState {
    eventId: string;
    keyType: string;
    nextKeyDigest: string;
    recoveryKeyDigest: string;
    proofs: Map<string, string>;
    documentDigest: string;
}

export class MicroLedgerInception {
    keyType: string;
    nextKeyDigest: string;
    recoveryKeyDigest: string;
    getId(): string {
        return utils.getCid(this);
    }
}

export class MicroLedger {
    inception: MicroLedgerInception;
    @Type(() => EventLog)
    events: EventLog[];
    getPreviousId(): string {
        if (this.events.length === 0) {
            return this.inception.getId();
        }
        return this.events[this.events.length - 1].getId();
    }

    saveEvent(signerSecret: Uint8Array, nextKeyDigest: Uint8Array, change: EventLogChange) {
        let signerKey = utils.secretToEdPublic(signerSecret);
        let previous = this.getPreviousId();
        let payload: EventLogPayload = {
            previous: previous,
            nextKeyDigest: utils.encode(nextKeyDigest),
            signerKey: utils.encode(signerKey),
            change: change,
        };
        let proof = utils.sign(payload, signerSecret);
        let eventLog = new EventLog();
        eventLog.payload = payload,
            eventLog.proof = utils.encode(proof)
        this.events.push(eventLog);
    }

    verify(cid: string): MicroLedgerState {
        let state = new MicroLedgerState();
        state.eventId = this.inception.getId();
        state.proofs = new Map<string, string>();
        state.nextKeyDigest = this.inception.nextKeyDigest;
        state.recoveryKeyDigest = this.inception.recoveryKeyDigest;
        const expectedCid = this.inception.getId();
        assert(expectedCid === cid, "InvalidId");
        if (!this.events) {
            return state;
        }
        for (const event of this.events) {
            const previousValid = event.payload.previous === state.eventId;
            assert(previousValid, "InvalidPrevious");
            const verified = utils.verify(utils.decode(event.proof), event.payload, utils.decode(event.payload.signerKey));
            assert(verified, "InvalidEventSignature");
            let currentSignerDigest = utils.encode(hash(utils.decode(event.payload.signerKey)));
            switch (typeof event.payload.change) {
                case typeof EventLogSetDocument:
                    const setDocChange = <EventLogSetDocument>event.payload.change;
                    assert(currentSignerDigest === state.nextKeyDigest, "InvalidSigner");
                    state.documentDigest = setDocChange.value;
                    break;
                case typeof EventLogSetProof:
                    const setProofChange = <EventLogSetProof>event.payload.change;
                    assert(currentSignerDigest === state.nextKeyDigest, "InvalidSigner");
                    state.proofs.set(setProofChange.key, setProofChange.value);
                    break;
                case typeof EventLogRecover:
                    const setRecChange = <EventLogRecover>event.payload.change;
                    assert(currentSignerDigest === state.nextKeyDigest, "InvalidSigner");
                    state.keyType = setRecChange.keyType;
                    state.recoveryKeyDigest = setRecChange.recoveryKeyDigest;
                    break;
            }
            state.eventId = utils.getCid(this);
            state.nextKeyDigest = event.payload.nextKeyDigest;
        }
        return state;
    }
}