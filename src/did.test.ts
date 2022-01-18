import { utils } from ".";
import {CreateIdentityInput, Identity} from "./did";

test('did create test',  () => {
    const secret = "bd6yg2qeifnixj4x3z2fclp5wd3i6ysjlfkxewqqt2thie6lfnkma";
    const expectedId = "bagaaieravphdumkejbohc7auy7c5od6dm6t2kw6ljhsoml3aoarzbhxxzeea";
    let input = new CreateIdentityInput();
    input.nextKeyDigest = utils.secretToKeyDigest(utils.decode(secret));
    input.recoveryKeyDigest = utils.secretToKeyDigest(utils.decode(secret));
    let did = Identity.new(input);
    expect(did.id).toBe(expectedId);
});