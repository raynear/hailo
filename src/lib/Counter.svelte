<script>
    import { onMount } from "svelte";
    import * as hailo from "./wasm/hailo.js";

    // let a = new BigUint64Array(1);
    // let b = new BigUint64Array(1);
    // let c = 0n;

    let a = 0;
    let b = 0;
    let c = 0;

    let setup;
    let proof;

    let result;

    onMount(async () => {
        // hailo = await _hailo();
        await hailo.default();
        setup = hailo.setup_params(4);
    });

    function prove() {
        proof = hailo.proof_generate(a, b, 7, setup);
    }

    function verify() {
        result = hailo.proof_verify(setup, 7, c, proof);
    }
</script>

a:<input bind:value={a} />
b:<input bind:value={b} />
c:<input bind:value={c} />

{result}

<button on:click={prove}> proof generate </button>

<button on:click={verify}> proof verify </button>
