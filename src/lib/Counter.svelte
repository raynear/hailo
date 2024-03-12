<script>
    import { onMount } from "svelte";
    import * as hailo from "./wasm/hailo.js";

    let nullifier = BigInt(0x456);
    let secret = BigInt(0xabc);
    let path_elements = BigUint64Array.from([2n, 5n, 7n, 14n, 23n]);
    let path_indices = BigUint64Array.from([0n, 0n, 1n, 1n, 0n]);

    let setup;
    let proof;

    let root =
        BigInt(
            0x00000000000000000000000000000000000000000000000000000010020445e0,
        );

    let result;

    onMount(async () => {
        // hailo = await _hailo();
        await hailo.default();
        setup = hailo.setup_params(10);
    });

    function prove() {
        proof = hailo.proof_generate(
            nullifier,
            secret,
            path_elements,
            path_indices,
            setup,
        );
    }

    function verify() {
        result = hailo.proof_verify(setup, nullifier, root, proof);
    }
</script>

nullifier:<input bind:value={nullifier} />
secret:<input bind:value={secret} />
root:<input bind:value={root} />

<br />
{result == undefined ? "" : result ? "Verified" : "Verify Failed"}
<br />

<button on:click={prove}> proof generate </button>

<button on:click={verify}> proof verify </button>
