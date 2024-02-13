#[cfg(not(target_family = "wasm"))]

fn main() {
    use hailo::hailo::{
        create_circuit, generate_keys, generate_proof, generate_setup_params, verify,
    };
    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 4;

    // Prepare the private and public inputs to the circuit!
    let constant = Fp::from(7);
    let a = Fp::from(2);
    let b = Fp::from(2);
    // let c = constant * a.square() * b.square();
    let c = a + b;

    // Instantiate the circuit with the private inputs.
    let circuit: MyCircuit<Fp> = create_circuit(a, b, constant);

    // Arrange the public input. We expose the multiplication result in row 0
    // of the instance column, so we position it there in our public inputs.
    let mut public_inputs: Vec<Fp> = vec![c];

    // Generate setup params
    let params = generate_setup_params(k);

    // Generate proving and verifying keys
    let empty_circuit: MyCircuit<Fp> = empty_circuit(constant);
    let (pk, vk) = generate_keys(&params, &empty_circuit);

    let proof = generate_proof(&params, &pk, circuit, &public_inputs);

    // Verify proof
    let verify = verify(&params, &vk, &public_inputs, proof);
    println!("Verify result: {:?}", verify);
}
