import assert from "assert";
import { Type } from "class-transformer";
import { EventLog } from "./event_log";
import { NextKey, utils } from ".";

export class MicroLedgerState {
    currentEventId: string;
    currentSignerKey: NextKey;
    currentRecoveryKey: NextKey;
    currentProofs: { [key: string]: string };
    currentDocument: string;
}

export class MicroLedgerInception {
    signerNextKey: NextKey;
    recoveryNextKey: NextKey;
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
        let expectedCid = await this.inception.getId();
        assert(expectedCid === cid);
        this.events.forEach(event => {
            let previousValid = event.payload.previous === state.currentEventId;
            assert(previousValid);
            // 
            switch (event.payload.change.type) {
                case "SetDocument":
                case "SetProof":
                case "SetRecovery":
            }
        });
        return state;
    }
}