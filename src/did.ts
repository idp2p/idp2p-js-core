import { IdDocument,CreateDocInput, Service } from "./did_doc";
import { utils } from "./main";
import { MicroLedger } from "./microledger";

export class IdentityInput{
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
    static async new(input: IdentityInput) : Promise<Identity> {
        let docInput = new CreateDocInput();
        docInput.agreementSecret = input.agreementSecret;
        docInput.assertionSecret = input.assertionSecret;
        docInput.authenticationSecret = input.authenticationSecret;
        docInput.service = input.service;
        let doc = IdDocument.from(docInput);
        let did = new Identity();
        did.microledger = new MicroLedger();
        did.document = doc;
        return did;
    }
    
}