//import {  instanceToPlain, plainToInstance } from "class-transformer";
import { CreateDocInput, IdDocument } from "./did_doc";
//const elliptic = require('elliptic');

test('did_doc parse', () => {
    /*let doc = new IdDocument();
    doc.id = "did:p2p:bagaaieratxin";
    doc.controller= "did:p2p:bagaaieratxi..";
    doc.context = [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
        "https://w3id.org/security/suites/x25519-2020/v1"
    ];
    doc.verificationMethod = [{
        id: "1",
        type: "2",
        controller: "3",
        publicKeyMultibase: "4"
    }];
    doc.assertionMethod = ["did:p2p:bagaaieratxib#wtyb2xhyvxolbd.."];
    doc.authentication= ["did:p2p:bagaaieratxib#3txadadmtke6d.."];
    let plain = instanceToPlain(doc);
    console.log(plainToInstance(IdDocument, plain));
    console.log(JSON.stringify(plain));
    expect(doc.id).toBe("did:p2p:bagaaieratxin");
    let input = new CreateDocInput();
    input.id = "1";
    input.assertionSecret = elliptic.utils.toArray(new Array(65).join('0'), 'hex');
    input.authenticationSecret = elliptic.utils.toArray(new Array(65).join('0'), 'hex');
    input.agreementSecret = elliptic.utils.toArray(new Array(65).join('0'), 'hex');
    input.services = [{
        id: "string",
        type: "string",
        serviceEndpoint: "string"
    }];
    let doc = create_doc(input);
    console.log(doc);*/
});

test('did_doc generate test', async () => {
    let input = new CreateDocInput();
    input.id = "bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja";
    input.services = [{
        id: "string",
        type: "string",
        serviceEndpoint: "string"
    }];
    input.assertionSecret = "bu4lbv3svya3ld5s6oq44mlj3vf6abyt2sktl6hla3ewrlwjat3gq";
    input.authenticationSecret = "b3zdrsdabskurlxvdibhgbsdfyjqjdyhzhjavfo6m6xfgx4eivltq";
    input.agreementSecret = "bf7zibj25vw2jfua7f2mph4cii7wlffw63pr5rianjq3wtmicwcxa";
    const doc = IdDocument.from(input);
    const expected_doc: IdDocument = {
        id: "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja",
        controller: "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja",
        context: [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/x25519-2020/v1"
        ],
        verificationMethod: [
            {
                id: "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja#bswfdlmfuec7wfl4hmv5yzt27ob43k6go7l5fiolgdmpfmm3dicqq",
                controller: "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja",
                type: "Ed25519VerificationKey2020",
                publicKeyMultibase: "bswfdlmfuec7wfl4hmv5yzt27ob43k6go7l5fiolgdmpfmm3dicqq"
            },
            {
                id: "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja#bq66f3qbf6utqercex7ikbozzpvouh2enq3xygevrxl52x2tnngja",
                controller: "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja",
                type: "Ed25519VerificationKey2020",
                publicKeyMultibase: "bq66f3qbf6utqercex7ikbozzpvouh2enq3xygevrxl52x2tnngja"
            },
            {
                id: "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja#bgwvuhdmqfkmydasxlu3mgjph6bdfykqzudnwnk2x372elnxfnqga",
                controller: "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja",
                type: "X25519KeyAgreementKey2020",
                publicKeyMultibase: "bgwvuhdmqfkmydasxlu3mgjph6bdfykqzudnwnk2x372elnxfnqga"
            }
        ],
        assertionMethod: [
            "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja#bswfdlmfuec7wfl4hmv5yzt27ob43k6go7l5fiolgdmpfmm3dicqq"
        ],
        authentication: [
            "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja#bq66f3qbf6utqercex7ikbozzpvouh2enq3xygevrxl52x2tnngja"
        ],
        keyAgreement: [
            "did:p2p:bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja#bgwvuhdmqfkmydasxlu3mgjph6bdfykqzudnwnk2x372elnxfnqga"
        ],
        service: [{
            id: "string",
            type: "string",
            serviceEndpoint: "string"
        }]
    };

    expect(doc).toEqual(expected_doc);
});