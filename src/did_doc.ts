import { Expose, Type } from 'class-transformer';
const EdDSA = require('elliptic').eddsa;
const ec = new EdDSA('ed25519');

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
}

export class CreateDocInput{
    id: string;
    assertionSecret: string;
    authenticationSecret: string;
    agreementSecret: string;
    services: Service[];
}

export function create_doc(input: CreateDocInput): IdDocument {
    var assertionKey = ec.keyFromSecret(input.assertionSecret);
    var authenticationKey = ec.keyFromSecret(input.authenticationSecret);
    var agreementKey = ec.keyFromSecret(input.agreementSecret);
    console.log(agreementKey);
    console.log(authenticationKey);
    console.log(assertionKey);
    let doc = new IdDocument();
    doc.id = input.id;
    doc.controller = `did:p2p:${input.id}`;
    doc.service = input.services;
    return doc;
}