import assert from "assert";
import { Type } from "class-transformer";
import { EventLog, EventLogSetRecoveryKeyChange, EventLogSetDocumentChange, EventLogSetProofChange } from "./event_log";
import { utils } from ".";

export class MicroLedgerState {
    eventId: string;
    signerNextKeyDigest: string;
    recoveryNextKeyDigest: string;
    proofs: Map<string, string>;
    documentDigest: string;
}

export class MicroLedgerInception {
    inceptionPublicKey: string;
    recoveryNextKeyDigest: string;
    async getId(): Promise<string> {
        return await utils.getCid(this);
    }
}

export class MicroLedger {
    inception: MicroLedgerInception;
    @Type(() => EventLog)
    events: EventLog[];
    async verify(cid: string): Promise<MicroLedgerState> {
        let state = new MicroLedgerState();
        state.eventId = await this.inception.getId();
        state.proofs = new Map<string, string>();
        state.recoveryNextKeyDigest = this.inception.recoveryNextKeyDigest;
        state.signerNextKeyDigest =  await utils.getDigest(this.inception.inceptionPublicKey);
        const expectedCid = await this.inception.getId();
        assert(expectedCid === cid);
        this.events.forEach(async event => {
            const previousValid = event.payload.previous === state.eventId;
            assert(previousValid);
            const verified = utils.verify(event.proof, event.payload, event.payload.signerPublicKey);
            assert(verified);
            let currentSignerDigest = await utils.getDigest(event.payload.signerPublicKey);
            switch (typeof event.payload.change) {
                case typeof EventLogSetDocumentChange:
                    const setDocChange = <EventLogSetDocumentChange> event.payload.change;
                    assert(currentSignerDigest === state.signerNextKeyDigest);
                    state.documentDigest = setDocChange.value; 
                    break;
                case typeof  EventLogSetProofChange:
                    const setProofChange = <EventLogSetProofChange> event.payload.change;
                    assert(currentSignerDigest === state.signerNextKeyDigest);
                    state.proofs.set(setProofChange.key, setProofChange.value);
                    break;
                case typeof  EventLogSetRecoveryKeyChange:
                    const setRecChange = <EventLogSetRecoveryKeyChange> event.payload.change;
                    assert(currentSignerDigest === state.recoveryNextKeyDigest);
                    state.recoveryNextKeyDigest = setRecChange.recoveryNextKeyDigest;
                    break;
            }
            state.eventId = await utils.getCid(this);
            state.signerNextKeyDigest = event.payload.signerNextKeyDigest;
        });
        return state;
    }
}