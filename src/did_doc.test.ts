//import {  instanceToPlain, plainToInstance } from "class-transformer";
import { CreateDocInput, create_doc } from "./did_doc";
const elliptic = require('elliptic');

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
    expect(doc.id).toBe("did:p2p:bagaaieratxin");*/
    let input = new CreateDocInput();
    input.id = "1";
    input.assertionSecret =  elliptic.utils.toArray(new Array(65).join('0'), 'hex');
    input.authenticationSecret =  elliptic.utils.toArray(new Array(65).join('0'), 'hex');
    input.agreementSecret =  elliptic.utils.toArray(new Array(65).join('0'), 'hex');
    input.services = [];
    let doc = create_doc(input);
    console.log(doc);
});