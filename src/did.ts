import { IdDocument,CreateDocInput, Service } from "./did_doc";
import { NextKey, utils } from "./main";
import { MicroLedger, MicroLedgerInception } from "./microledger";

export class CreateIdentityInput{
    signerSecret: string;
    recoverySecret: string;
    assertionSecret: string;
    authenticationSecret: string;
    agreementSecret: string;
    service: Service[];
}

export class Identity {
    id: string;
    microledger: MicroLedger;
    document: IdDocument;
    async getDigest(): Promise<string>{
       return utils.getDigest(this);
    }
    static async new(input: CreateIdentityInput) : Promise<Identity> {
        let docInput = new CreateDocInput();
        docInput.agreementSecret = input.agreementSecret;
        docInput.assertionSecret = input.assertionSecret;
        docInput.authenticationSecret = input.authenticationSecret;
        docInput.service = input.service;
        let doc = IdDocument.from(docInput);
        let did = new Identity();
        let inception = new MicroLedgerInception();
        inception.signerNextKey = await NextKey.from(input.signerSecret);
        inception.recoveryNextKey = await NextKey.from(input.recoverySecret);
        did.microledger =  new MicroLedger();
        did.microledger.inception = inception;
        did.document = doc;
        return did;
    }
    
}