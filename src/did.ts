import { IdDocument } from "./did_doc";
import { ED25519, utils } from ".";
import { MicroLedger, MicroLedgerInception } from "./microledger";
import { EventLogSetDocument } from "./event_log";

export class CreateIdentityInput {
    nextKeyDigest: Uint8Array;
    recoveryKeyDigest: Uint8Array;
}
export class Identity {
    id: string;
    microledger: MicroLedger;
    document: IdDocument;
    getDigest(): Uint8Array {
        return utils.getDigest(this);
    }
    setDocument(signerSecret: Uint8Array, nextKeyDigest: Uint8Array, doc: IdDocument) {
        this.document = doc;
        const change = new EventLogSetDocument();
        change.value = utils.encode(utils.getDigest(doc));
        this.microledger.saveEvent(signerSecret, nextKeyDigest, change);
    }

    static new(input: CreateIdentityInput): Identity {
        let did = new Identity();
        let inception = new MicroLedgerInception();
        inception.keyType = ED25519;
        inception.nextKeyDigest = utils.encode(input.nextKeyDigest);
        inception.recoveryKeyDigest = utils.encode(input.recoveryKeyDigest);
        did.microledger = new MicroLedger();
        did.id = utils.getCid(inception);
        did.microledger.inception = inception;
        return did;
    }

}