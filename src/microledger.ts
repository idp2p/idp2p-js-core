import { Type } from "class-transformer";
import { EventLog } from "./event_log";

export class MicroLedgerInception{}

export class MicroLedger{
    id : string;
    inception: MicroLedgerInception;
    @Type(() => EventLog)
    events: EventLog[];
}