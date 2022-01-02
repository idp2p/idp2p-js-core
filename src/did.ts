import { IdDocument } from "./did_doc";
import { ED25519, utils } from ".";
import { MicroLedger, MicroLedgerInception } from "./microledger";
import { EventLogSetDocument } from "./event_log";

export class CreateIdentityInput {
    nextSecret: string;
    recoverySecret: string;
}
export class Identity {
    id: string;
    microledger: MicroLedger;
    document: IdDocument;
    async getDigest(): Promise<string> {
        return utils.getDigest(this);
    }
    async setDocument(signerSecret: string, nextKeyDigest: string, doc: IdDocument) {
        this.document = doc;
        const change = new EventLogSetDocument();
        change.value = await utils.getDigest(doc);
        this.microledger.saveEvent(signerSecret, nextKeyDigest, change);
    }

    static async new(input: CreateIdentityInput): Promise<Identity> {
        let did = new Identity();
        let inception = new MicroLedgerInception();
        inception.keyType = ED25519;
        inception.nextKeyDigest = await utils.secretToKeyDigest(input.nextSecret);
        inception.recoveryKeyDigest = await utils.secretToKeyDigest(input.recoverySecret);
        did.microledger = new MicroLedger();
        did.microledger.inception = inception;
        return did;
    }

}