import { Expose, Type } from 'class-transformer';
import { ED25519, utils, X25519 } from '.';

export class Service {
    id: string;
    type: string;
    serviceEndpoint: string;
}

export class VerificationMethod {
    id: string;
    controller: string;
    type: string;
    publicKeyMultibase: string;
}

export class IdDocument {
    id: string;
    controller: string;
    @Expose({ name: "@context" })
    @Type(() => String)
    context: string[] = [];
    @Type(() => VerificationMethod)
    verificationMethod: VerificationMethod[] = [];
    assertionMethod: string[] = [];
    authentication: string[] = [];
    keyAgreement: string[] = [];
    @Type(() => Service)
    service: Service[] = [];

    static from(input: CreateDocInput) : IdDocument{
        const assertionKey = utils.encode(input.assertionKey);
        const authenticationKey = utils.encode(input.authenticationKey);
        const agreementKey = utils.encode(input.agreementKey);
        let doc = new IdDocument();
        doc.id =  `did:p2p:${input.id}`;
        doc.controller = `did:p2p:${input.id}`;
        doc.service = input.service;
        let assertionVerMethod = new VerificationMethod();
        assertionVerMethod.controller = `did:p2p:${input.id}`;
        assertionVerMethod.type = ED25519;
        assertionVerMethod.id = `did:p2p:${input.id}#${assertionKey}`;
        assertionVerMethod.publicKeyMultibase = assertionKey;
        doc.verificationMethod.push(assertionVerMethod);
        doc.assertionMethod.push(assertionVerMethod.id);
    
        let authenticationVerMethod = new VerificationMethod();
        authenticationVerMethod.controller = `did:p2p:${input.id}`;
        authenticationVerMethod.type = ED25519;
        authenticationVerMethod.id = `did:p2p:${input.id}#${authenticationKey}`;
        authenticationVerMethod.publicKeyMultibase = authenticationKey;
        doc.verificationMethod.push(authenticationVerMethod);
        doc.authentication.push(authenticationVerMethod.id);
    
        let agreementVerMethod = new VerificationMethod();
        agreementVerMethod.controller = `did:p2p:${input.id}`;
        agreementVerMethod.type = X25519;
        agreementVerMethod.id = `did:p2p:${input.id}#${agreementKey}`;;
        agreementVerMethod.publicKeyMultibase = agreementKey;
        doc.verificationMethod.push(agreementVerMethod);
        doc.keyAgreement.push(agreementVerMethod.id);
    
        doc.context.push("https://www.w3.org/ns/did/v1");
        doc.context.push("https://w3id.org/security/suites/ed25519-2020/v1");
        doc.context.push("https://w3id.org/security/suites/x25519-2020/v1");
        doc.service = input.service;
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