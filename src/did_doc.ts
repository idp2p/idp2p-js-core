import { Expose, Type } from 'class-transformer';
import { ED25519, utils, X25519 } from '.';

export class Service {
    id: string;
    type: string;
    serviceEndpoint: string;
    constructor(id: string, typ: string, endpoint: string) {
        this.id = id;
        this.type = typ;
        this.serviceEndpoint = endpoint;
     }
}

export class VerificationMethod {
    id: string;
    controller: string;
    type: string;
    publicKeyMultibase: string;
    constructor(id: string, typ: string, key: string) {
       this.id = `did:p2p:${id}#${key}`;
       this.controller = `did:p2p:${id}`;
       this.type = typ;
       this.publicKeyMultibase = key;
    }
}

export class IdDocument {
    @Expose({ name: "@context" })
    @Type(() => String)
    context: string[];
    id: string;
    controller: string;
    @Type(() => VerificationMethod)
    verificationMethod: VerificationMethod[];
    assertionMethod: string[] ;
    authentication: string[];
    keyAgreement: string[];
    @Type(() => Service)
    service: Service[];

    static from(input: CreateDocInput) : IdDocument{
        const assertionKey = utils.encode(input.assertionKey);
        const authenticationKey = utils.encode(input.authenticationKey);
        const agreementKey = utils.encode(input.agreementKey);
        let context = [];
        context.push("https://www.w3.org/ns/did/v1");
        context.push("https://w3id.org/security/suites/ed25519-2020/v1");
        context.push("https://w3id.org/security/suites/x25519-2020/v1");
        let assertionVerMethod = new VerificationMethod(input.id, ED25519, assertionKey);
        let authenticationVerMethod = new VerificationMethod(input.id, ED25519, authenticationKey);
        let agreementVerMethod = new VerificationMethod(input.id, X25519, agreementKey);

        let doc = new IdDocument();
        doc.context = context;
        doc.id =  `did:p2p:${input.id}`;
        doc.controller = `did:p2p:${input.id}`;
        doc.service = input.service;
        doc.verificationMethod = [assertionVerMethod, authenticationVerMethod, agreementVerMethod];
        doc.assertionMethod = [assertionVerMethod.id];
        doc.authentication = [authenticationVerMethod.id];
        doc.keyAgreement = [agreementVerMethod.id];
        return doc;
    } 
}

export class CreateDocInput{
    id: string;
    assertionKey: Uint8Array;
    authenticationKey: Uint8Array;
    agreementKey: Uint8Array;
    service: Service[];
}