import { utils } from ".";

test('cid generate test', async () => {
  let input = {
    signer_key: {
      type: "Ed25519VerificationKey2020",
      public: "btvd3rhsk7xtocytpe3dfry34uldcn6qwfhh6eu4bcgq2miu2246q"
    },
    recovery_key: {
      type: "Ed25519VerificationKey2020",
      digest: "btvd3rhsk7xtocytpe3dfry34uldcn6qwfhh6eu4bcgq2miu2246q"
    }
  }
  const id = await utils.getCid(input);
  const expected_id = "bagaaieraxyvdfdi2doyf4pu2r5wam53sfj5kxpqbqsrtbnshmbiufs3bqina";

  expect(id).toEqual(expected_id);
});

test('proof test', async () => {
   const secret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
   const sig = await utils.sign({text: "abc"}, secret);
   const publicKey = utils.secretToEdPublic(secret);
   const isValid = await utils.verify(sig, {text: "abc"}, publicKey);
   expect(isValid).toBe(true);
   expect(sig).toEqual("b3jn2fbfhu3fomlycdn65iirwt3bsmossbxjelhc6bvuac5fxqgtnd235ygvfbzelmsedonu7dxfppgxyuc4t7hx6vvkorwumtetkwci");
});