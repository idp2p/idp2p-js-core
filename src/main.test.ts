import { utils } from "./main";

test('cid generate test', async () => {
    let input = {
        signer_key: {
            type: "Ed25519VerificationKey2020",
            public: "brgzkmbdnyevdth3sczvxjumd6bdl6ngn6eqbsbpazuvq42bfzk2a"
          },
          recovery_key: {
            type: "Ed25519VerificationKey2020",
            digest: "btvd3rhsk7xtocytpe3dfry34uldcn6qwfhh6eu4bcgq2miu2246q"
          }
    }
    const id = await utils.getCid(input);
    const expected_id = "bagaaiera62a5raawyfngt4d7w3jetwrks2k2xp3bcnuzhxjeqteordlsuzja"; 

    expect(id).toEqual(expected_id);
});