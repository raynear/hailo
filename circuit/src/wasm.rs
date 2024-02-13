use crate::hailo::{
    create_circuit, empty_circuit, generate_keys, generate_proof, generate_setup_params, verify,
    MyCircuit,
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
pub fn proof_generate(a: u8, b: u8, constant: u8, params_bytes: &[u8]) -> Uint8Array {
    log("proving...");

    let params = Params::<EqAffine>::read(&mut BufReader::new(params_bytes))
        .expect("params should not fail to read");

    let constant = Fp::from(constant as u64);
    let a = Fp::from(a as u64);
    let b = Fp::from(b as u64);

    let c = a + b;
    let public_inputs: Vec<Fp> = vec![c];

    // Generate proving key
    let empty_circuit: MyCircuit<Fp> = empty_circuit(constant);
    let (pk, _vk) = generate_keys(&params, &empty_circuit);

    // Generate proof
    let circuit: MyCircuit<Fp> = create_circuit(a, b, constant);
    let proof = generate_proof(&params, &pk, circuit, &public_inputs);

    log("proved");
    copy_vec_to_u8arr(&proof)
}

#[wasm_bindgen]
pub fn proof_verify(params_bytes: &[u8], constant: u8, c: u8, proof: &[u8]) -> bool {
    log("verifying...");

    let params = Params::<EqAffine>::read(&mut BufReader::new(params_bytes))
        .expect("params should not fail to read");

    let constant = Fp::from(constant as u64);

    // Generate verifying key
    let empty_circuit = empty_circuit(constant);
    let vk = keygen_vk(&params, &empty_circuit).expect("vk should not fail to generate");

    let c = Fp::from(c as u64);

    // Transform params for verify function
    let public_input: Vec<Fp> = vec![c];
    let proof_vec = proof.to_vec();

    // Verify the proof and public input
    let ret_val = verify(&params, &vk, &public_input, proof_vec);

    log("verified");
    match ret_val {
        Err(_) => false,
        _ => true,
    }
}
