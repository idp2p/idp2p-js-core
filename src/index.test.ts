import { utils } from ".";

test('proof test', () => {
  const secret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
  const sig = utils.sign({ text: "abc" }, utils.decode(secret));
  const publicKey = utils.secretToEdPublic(utils.decode(secret));
  const isValid = utils.verify(sig, { text: "abc" }, publicKey);
  expect(isValid).toBe(true);
  expect(utils.encode(sig)).toEqual("bcrbifuc6qdxrig6y2dq7hj4jbysolc26zyby6gl326tkrb32744gqjrywrkposl3giv7bvswcu4p3i437xkjev4j4ksp7yqu73fp2ci");
});

test('cid test', () => {
  let data = {
    "name": "John Doe"
  };
  let expected = "bagaaieraotmu6ay364t223hj4akn7amds6rpwquuavx54demvy5e4vkn5uuq";
  let cid = utils.getCid(data);
  expect(expected).toBe(cid);
});

test('hash test', async () => {
  let data = {
    "name": "John Doe"
  };
  const expected = "botmu6ay364t223hj4akn7amds6rpwquuavx54demvy5e4vkn5uuq";
  let digest = utils.encode(utils.getDigest(data));
  expect(expected).toBe(digest);
});

test('verification key test', async () => {
  const secret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
  const expected = "brgzkmbdnyevdth3sczvxjumd6bdl6ngn6eqbsbpazuvq42bfzk2a";
  let publicKey = utils.encode(utils.secretToEdPublic(utils.decode(secret)));
  expect(publicKey).toBe(expected);
});

test('verification digest test', async () => {
  const secret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
  const expected = "bcodiqdow4rvnu4o2wwtpv6dvjjsd63najdeazekh4w3s2dyb2tvq";
  let digest = await utils.encode(utils.secretToKeyDigest(utils.decode(secret)));
  expect(digest).toBe(expected);
});

test('key agreement test', async () => {
  const secret = "bclc5pn2tfuhkqmupbr3lkyc5o4g4je6glfwkix6nrtf7hch7b3kq";
  const expected = "bbgitzmdocc3y2gvcmtiihr2gyw4xjppux7ea3gdo6afwy6gbrmpa";
  let publicKey = utils.encode(utils.secretToXPublic(utils.decode(secret)));
  expect(publicKey).toBe(expected);
});