import { IdDocument } from "./did_doc";
import { MicroLedger } from "./microledger";

export interface Identity {
    id: string;
    microledger: MicroLedger;
    did_doc: IdDocument;
}