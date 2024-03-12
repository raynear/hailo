pub mod chips;
pub mod circuits;
pub mod wasm;

use crate::circuits::tornado::TornadoCircuit;
use halo2_proofs::{
    arithmetic::Field,
    circuit::Value,
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Error, ProvingKey, SingleVerifier,
        VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand_core::OsRng;

// Generates a proof
pub fn generate_proof(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: TornadoCircuit<Fp>,
    pub_input: &Vec<Fp>,
) -> Vec<u8> {
    println!("Generating proof...");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(
        params,
        pk,
        &[circuit],
        &[&[pub_input]],
        OsRng,
        &mut transcript,
    )
    .expect("Prover should not fail");
    transcript.finalize()
}

// Verifies the proof
pub fn verify(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    pub_input: &Vec<Fp>,
    proof: Vec<u8>,
) -> Result<(), Error> {
    println!("Verifying proof...");
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof(params, vk, strategy, &[&[pub_input]], &mut transcript)
}

pub fn generate_setup_params(k: u32) -> Params<EqAffine> {
    Params::<EqAffine>::new(k)
}

pub fn empty_circuit() -> TornadoCircuit<Fp> {
    TornadoCircuit {
        nullifier: Value::unknown(),
        secret: Value::unknown(),
        path_elements: [Value::unknown(); 5].to_vec(), // [Value::unknown(); BINARY_LENGTH],
        path_indices: [Value::unknown(); 5].to_vec(),  // [Value::unknown(); BINARY_LENGTH],
    }
}

// Generates the verifying and proving keys. We can pass in an empty circuit to generate these
pub fn generate_keys(
    params: &Params<EqAffine>,
    circuit: &TornadoCircuit<Fp>,
) -> (ProvingKey<EqAffine>, VerifyingKey<EqAffine>) {
    // just to emphasize that for vk, pk we don't need to know the value of `x`
    let vk = keygen_vk(params, circuit).expect("vk should not fail");
    let pk = keygen_pk(params, vk.clone(), circuit).expect("pk should not fail");
    (pk, vk)
}

// Creates a circuit from two vector inputs
pub fn create_circuit(
    nullifier: Fp,
    secret: Fp,
    path_elements: Vec<Fp>,
    path_indices: Vec<Fp>,
) -> TornadoCircuit<Fp> {
    // Create circuit from inputs

    let nullifier = Value::known(nullifier);
    let secret = Value::known(secret);
    let path_elements: Vec<Value<Fp>> = path_elements.iter().map(|e| Value::known(*e)).collect();
    let path_indices = path_indices.iter().map(|e| Value::known(*e)).collect();

    TornadoCircuit {
        nullifier,
        secret,
        path_elements,
        path_indices,
    }
}

pub fn hash_value(value: Fp) -> Fp {
    hash_values(vec![value, value])
}
pub fn hash_values(values: Vec<Fp>) -> Fp {
    values.iter().product()
}

pub fn compute_root(leaf: Fp, path_elements: Vec<Fp>, path_indices: Vec<Fp>) -> Fp {
    assert!(path_elements.len() == path_indices.len());

    let mut node = leaf;
    for i in 0..path_elements.len() {
        let mut left = node;
        let mut right = path_elements[i];

        (left, right) = if path_indices[i] == Fp::ZERO {
            (left, right)
        } else {
            (right, left)
        };

        node = hash_values(vec![left, right]);
    }
    node
}
