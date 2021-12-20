import { Type } from "class-transformer";
import { EventLog } from "./event_log";
import { RecoveryKey, SignerKey, utils } from "./main";

export class MicroLedgerInception {
    signer_key: SignerKey;
    recovery_key: RecoveryKey;
    async getId(): Promise<string> {
        return await utils.getCid(this);
    }
}

export class MicroLedger {
    inception: MicroLedgerInception;
    @Type(() => EventLog)
    events: EventLog[];
}