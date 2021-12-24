import { instanceToPlain, plainToInstance } from "class-transformer";
import {CreateIdentityInput, Identity} from "./did";

test('did parse', async () => {
    let input = new CreateIdentityInput();
    input.assertionSecret = "bu4lbv3svya3ld5s6oq44mlj3vf6abyt2sktl6hla3ewrlwjat3gq";
    input.authenticationSecret = "b3zdrsdabskurlxvdibhgbsdfyjqjdyhzhjavfo6m6xfgx4eivltq";
    input.agreementSecret = "bf7zibj25vw2jfua7f2mph4cii7wlffw63pr5rianjq3wtmicwcxa";
    input.recoverySecret = "bf7zibj25vw2jfua7f2mph4cii7wlffw63pr5rianjq3wtmicwcxa";
    input.inceptionSecret = "bf7zibj25vw2jfua7f2mph4cii7wlffw63pr5rianjq3wtmicwcxa";
    input.service = [{
        id: "string",
        type: "string",
        serviceEndpoint: "string"
    }];
    let did = await Identity.new(input);
    let plain = instanceToPlain(did);
    console.log(plainToInstance(Identity, plain));
    let str = JSON.stringify(plain);
    console.log(str);
    //expect(doc.id).toBe("did:p2p:bagaaieratxin");
});