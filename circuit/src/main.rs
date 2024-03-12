use hailo::circuits::tornado::TornadoCircuit;
use hailo::{compute_root, hash_value, hash_values};
use hailo::{
    create_circuit, empty_circuit, generate_keys, generate_proof, generate_setup_params, verify,
};
use halo2_proofs::pasta::Fp;
use halo2_proofs::{circuit::Value, dev::MockProver};

fn main() {
    let nullifier = Fp::from(0x456);
    let secret = Fp::from(0xabc);
    let path_elements: Vec<Fp> = vec![2, 5, 7, 14, 23].iter().map(|e| Fp::from(*e)).collect();
    let path_indices: Vec<Fp> = vec![0, 0, 1, 1, 0].iter().map(|e| Fp::from(*e)).collect();

    let circuit = TornadoCircuit {
        nullifier: Value::known(nullifier),
        secret: Value::known(secret),
        path_elements: path_elements.iter().map(|e| Value::known(*e)).collect(),
        path_indices: path_indices.iter().map(|e| Value::known(*e)).collect(),
    };

    let commitment = hash_values(vec![nullifier, secret]);
    println!("commitment {:?}", commitment);

    let root = compute_root(
        commitment.clone(),
        path_elements.clone(),
        path_indices.clone(),
    );
    println!("root {:?}", root);

    let nullifier_hash = hash_value(nullifier);
    println!("nullifier_hash {:?}", nullifier_hash);

    let public_input = vec![nullifier_hash, root];
    let prover = MockProver::run(10, &circuit, vec![public_input.clone()]).unwrap();

    println!("MAIN prover: {:?}", prover.verify());
    // assert!(prover.verify().is_ok());

    let params = generate_setup_params(10);

    let public_inputs: Vec<Fp> = vec![nullifier_hash, root];

    // Generate proving key
    let empty_circuit: TornadoCircuit<Fp> = empty_circuit();
    let (pk, vk) = generate_keys(&params, &empty_circuit);

    let circuit: TornadoCircuit<Fp> = create_circuit(
        nullifier,
        secret,
        path_elements.clone(),
        path_indices.clone(),
    );
    let proof = generate_proof(&params, &pk, circuit, &public_inputs);

    let proof_vec = proof.to_vec();

    let ret_val = verify(&params, &vk, &public_input, proof_vec);

    match ret_val {
        Err(_) => println!("failed"),
        _ => println!("success"),
    }
}
