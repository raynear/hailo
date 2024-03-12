use crate::circuits::tornado::TornadoCircuit;
use crate::{
    compute_root, create_circuit, empty_circuit, generate_keys, generate_proof,
    generate_setup_params, hash_value, hash_values, verify,
};
use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::keygen_vk,
    poly::commitment::Params,
};
use js_sys::Uint8Array;
use std::io::BufReader;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn copy_vec_to_u8arr(v: &Vec<u8>) -> Uint8Array {
    let u8_arr = Uint8Array::new_with_length(v.len() as u32);
    u8_arr.copy_from(v);
    u8_arr
}

#[wasm_bindgen]
pub fn setup_params(k: u32) -> Uint8Array {
    log("running setup");

    // Generate setup params
    let params = generate_setup_params(k);
    let mut buf = vec![];
    params.write(&mut buf).expect("Can write params");

    copy_vec_to_u8arr(&buf)
}

#[wasm_bindgen]
pub fn proof_generate(
    nullifier: u64,
    secret: u64,
    path_elements: Vec<u64>,
    path_indices: Vec<u64>,
    params_bytes: &[u8],
) -> Uint8Array {
    log("proving...");

    let params = Params::<EqAffine>::read(&mut BufReader::new(params_bytes))
        .expect("params should not fail to read");

    let nullifier = Fp::from(nullifier as u64);
    let secret = Fp::from(secret as u64);

    let path_elements: Vec<Fp> = path_elements.iter().map(|e| Fp::from(*e)).collect();
    let path_indices: Vec<Fp> = path_indices.iter().map(|e| Fp::from(*e)).collect();

    let commitment = hash_values(vec![nullifier, secret]);
    log(format!("commitment {:?}", commitment).as_str());

    let root = compute_root(commitment, path_elements.clone(), path_indices.clone());
    log(format!("root {:?}", root).as_str());

    let nullifier_hash = hash_value(nullifier);
    log(format!("nullifier_hash {:?}", nullifier_hash).as_str());

    let public_inputs: Vec<Fp> = vec![nullifier_hash, root];

    // Generate proving key
    let empty_circuit: TornadoCircuit<Fp> = empty_circuit();
    let (pk, _vk) = generate_keys(&params, &empty_circuit);

    // Generate proof
    let circuit: TornadoCircuit<Fp> =
        create_circuit(nullifier, secret, path_elements, path_indices);
    let proof = generate_proof(&params, &pk, circuit, &public_inputs);

    log("proved");
    copy_vec_to_u8arr(&proof)
}

#[wasm_bindgen]
pub fn proof_verify(params_bytes: &[u8], nullifier: u64, root: u64, proof: &[u8]) -> bool {
    log("verifying...");

    let params = Params::<EqAffine>::read(&mut BufReader::new(params_bytes))
        .expect("params should not fail to read");

    // Generate verifying key
    let empty_circuit = empty_circuit();
    let vk = keygen_vk(&params, &empty_circuit).expect("vk should not fail to generate");

    let nullifier = Fp::from(nullifier);
    let nullifier_hash = hash_value(nullifier);
    log(format!("nullifier_hash {:?}", nullifier_hash).as_str());

    // Transform params for verify function
    let root = Fp::from(root);
    let public_input: Vec<Fp> = vec![nullifier_hash, root];
    let proof_vec = proof.to_vec();

    // Verify the proof and public input
    let ret_val = verify(&params, &vk, &public_input, proof_vec);

    log("verified");
    match ret_val {
        Err(_) => false,
        _ => true,
    }
}
