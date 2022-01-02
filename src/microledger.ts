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
    async getId(): Promise<string> {
        return await utils.getCid(this);
    }
}

export class MicroLedger {
    inception: MicroLedgerInception;
    @Type(() => EventLog)
    events: EventLog[];
    async getPreviousId(): Promise<string> {
        if (this.events.length === 0) {
            return await this.inception.getId();
        }
        return await this.events[this.events.length - 1].getId();
    }

    async saveEvent(signerSecret: string, nextKeyDigest: string, change: EventLogChange) {
        let signerKey = utils.secretToEdPublic(signerSecret);
        let previous = await this.getPreviousId();
        let payload: EventLogPayload = {
            previous: previous,
            nextKeyDigest: nextKeyDigest,
            signerKey: signerKey,
            change: change,
        };
        let proof = await utils.sign(payload, signerSecret);
        let eventLog = new EventLog();
        eventLog.payload = payload,
            eventLog.proof = proof
        this.events.push(eventLog);
    }

    async verify(cid: string): Promise<MicroLedgerState> {
        let state = new MicroLedgerState();
        state.eventId = await this.inception.getId();
        state.proofs = new Map<string, string>();
        state.nextKeyDigest = this.inception.nextKeyDigest;
        state.recoveryKeyDigest = this.inception.recoveryKeyDigest;
        const expectedCid = await this.inception.getId();
        assert(expectedCid === cid, "InvalidId");
        if (!this.events) {
            return state;
        }
        for (const event of this.events) {
            const previousValid = event.payload.previous === state.eventId;
            assert(previousValid, "InvalidPrevious");
            const verified = utils.verify(event.proof, event.payload, event.payload.signerKey);
            assert(verified, "InvalidEventSignature");
            let currentSignerDigest = await utils.getDigest(event.payload.signerKey);
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
            state.eventId = await utils.getCid(this);
            state.nextKeyDigest = event.payload.nextKeyDigest;
        }
        return state;
    }
}