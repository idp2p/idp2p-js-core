import { utils } from ".";
import { CreateDocInput, IdDocument } from "./did_doc";
test('did_doc generate test', () => {
    let input = new CreateDocInput();
    input.id = "bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja";
    input.service = [{
        id: "string",
        type: "string",
        serviceEndpoint: "string"
    }];
    input.assertionKey = utils.decode("bswfdlmfuec7wfl4hmv5yzt27ob43k6go7l5fiolgdmpfmm3dicqq");
    input.authenticationKey = utils.decode("bq66f3qbf6utqercex7ikbozzpvouh2enq3xygevrxl52x2tnngja");
    input.agreementKey = utils.decode("bgwvuhdmqfkmydasxlu3mgjph6bdfykqzudnwnk2x372elnxfnqga");
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

