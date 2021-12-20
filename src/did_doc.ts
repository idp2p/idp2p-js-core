import { Expose, Type } from 'class-transformer';
import { ED25519, utils, X25519 } from './main';

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
    context: string[];
    @Type(() => VerificationMethod)
    verificationMethod: VerificationMethod[];
    assertionMethod: string[];
    authentication: string[];
    keyAgreement: string[];
    @Type(() => Service)
    service: Service[];

    constructor(){
        this.context = [];
        this.verificationMethod = [];
        this.assertionMethod = [];
        this.authentication = [];
        this.keyAgreement = [];
        this.service = [];
    }
}

export class CreateDocInput{
    id: string;
    assertionSecret: string;
    authenticationSecret: string;
    agreementSecret: string;
    services: Service[];
}

export function create_doc(input: CreateDocInput): IdDocument {
    const assertionKey = utils.secretToEdPublic(input.assertionSecret);
    const authenticationKey = utils.secretToEdPublic(input.authenticationSecret);
    const agreementKey = utils.secretToXPublic(input.agreementSecret);
    let doc = new IdDocument();
    doc.id =  `did:p2p:${input.id}`;
    doc.controller = `did:p2p:${input.id}`;
    doc.service = input.services;
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
    doc.service = input.services;
    return doc;
}