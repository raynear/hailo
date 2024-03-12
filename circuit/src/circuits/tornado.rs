use crate::chips::{
    merkle::MerkleChip,
    tornado::{TornadoChip, TornadoConfig},
};
use group::ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};

#[derive(Debug, Default)]
pub struct TornadoCircuit<F> {
    pub nullifier: Value<F>,
    pub secret: Value<F>,
    pub path_elements: Vec<Value<F>>,
    pub path_indices: Vec<Value<F>>,
}

impl<F: PrimeField> Circuit<F> for TornadoCircuit<F> {
    type Config = TornadoConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        TornadoChip::configure(meta, advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let tornado_chip = TornadoChip::construct(config.clone());

        // step 1: nullifier hash
        let nullifier_hash_cell = tornado_chip.compute_hash(
            layouter.namespace(|| "get nullifier hash"),
            self.nullifier,
            self.nullifier,
        )?;
        println!("nullifier_hash_cell {nullifier_hash_cell:?}");
        layouter.constrain_instance(nullifier_hash_cell.cell(), config.clone().instance, 0)?;

        // step 2: compute commitment
        let commitment_hash_cell = tornado_chip.compute_hash(
            layouter.namespace(|| "get nullifier hash"),
            self.nullifier,
            self.secret,
        )?;
        println!("commitment_hash_cell {commitment_hash_cell:?}");
        let merkle_chip = MerkleChip::construct(config.clone().merkle_config);
        let merkle_root_cell = merkle_chip.prove_tree_root(
            layouter.namespace(|| "prove merkle tree"),
            commitment_hash_cell,
            self.path_elements.clone(),
            self.path_indices.clone(),
        )?;
        println!("merkle_root_cell: {merkle_root_cell:?}");
        layouter.constrain_instance(merkle_root_cell.cell(), config.clone().instance, 1)?;

        Ok(())
    }
}
