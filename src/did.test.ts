import { instanceToPlain, plainToInstance } from "class-transformer";
import {CreateIdentityInput, Identity} from "./did";

test('did parse', async () => {
    let input = new CreateIdentityInput();
    input.recoverySecret = "bf7zibj25vw2jfua7f2mph4cii7wlffw63pr5rianjq3wtmicwcxa";
    input.nextSecret = "bf7zibj25vw2jfua7f2mph4cii7wlffw63pr5rianjq3wtmicwcxa";
    let did = await Identity.new(input);
    let plain = instanceToPlain(did);
    console.log(plainToInstance(Identity, plain));
    let str = JSON.stringify(plain);
    console.log(str);
    //expect(doc.id).toBe("did:p2p:bagaaieratxin");
});