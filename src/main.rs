use std::{
    fs::{self, File}, io::{BufRead, BufReader}, marker::PhantomData, ops::Mul
};

// use super::*;
use halo2_ecc::{
    bigint::{big_is_zero::crt, check_carry_mod_to_zero::crt}, bn254::{self, pairing::{PairingChip}, Fp12Chip, Fp2Chip, FpChip}, ecc::EccChip, fields::FieldChip, halo2_base};
use halo2_ecc::{
    // fields::FpStrategy
    fields::FpStrategy, 
    // halo2_proofs::halo2curves::bn256::G2Affine
};

use halo2_base::{
    gates::{
        circuit::{
            builder::{
                self, BaseCircuitBuilder, RangeCircuitBuilder
            }, 
            CircuitBuilderStage
        }, 
        RangeChip
    }, 
    utils::{
        BigPrimeField, testing::gen_proof
    }, 
    Context, halo2_proofs::{
        dev::{
            metadata::Column, MockProver
        }, halo2curves::{
            bn256::{
                pairing, G1Affine, G2Affine, G1
            }
        }, plonk::{
            Selector, Advice
        }, poly::commitment::Prover
    },
    halo2_proofs::halo2curves::bn256::{self, Fr}
};

use halo2curves::group::Curve;
// use halo2curves::bn256::Fr;
// use halo2curves::bn256::pairing;
use rand::rngs::StdRng;
use rand_core::{Error, SeedableRng};
use serde::{Deserialize, Serialize};

mod utils;

use utils::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct PairingCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

fn pairing_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: PairingCircuitParams,
    P: G1Affine,
    Q: G2Affine,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let chip = PairingChip::new(&fp_chip);
    let P_assigned = chip.load_private_g1_unchecked(ctx, P);
    let Q_assigned = chip.load_private_g2_unchecked(ctx, Q);
    // test optimal ate pairing
    let f = chip.pairing(ctx, &Q_assigned, &P_assigned);
    let actual_f = pairing(&P, &Q);
    let fp12_chip = Fp12Chip::new(&fp_chip);
    // cannot directly compare f and actual_f because `Gt` has private field `Fq12`
    assert_eq!(
        format!("Gt({:?})", fp12_chip.get_assigned_value(&f.into())),
        format!("{actual_f:?}")
    );
}




#[derive(Clone, Debug)]
pub struct TestCircuit<F: BigPrimeField> {
    _f: PhantomData<F>
}

impl<F: BigPrimeField> TestCircuit<F> {
    pub fn new() -> Self {
        Self {
            _f: PhantomData
        }
    }

    pub fn synthesize(
        builder:&mut BaseCircuitBuilder<bn256::Fr>,
        fp_chip: &FpChip<bn256::Fr>,
    ) -> Result<(), Error> {
        let pairing_chip = PairingChip::new(fp_chip);
        // let verif_key = get_verification_key();
        let verif_key = VerificationKey {
            alpha1: G1Affine::random(&mut rand::thread_rng()),
            beta2: G2Affine::random(&mut rand::thread_rng()),
            gamma2: G2Affine::random(&mut rand::thread_rng()),
            delta2: G2Affine::random(&mut rand::thread_rng()),
            ic: vec![G1Affine::random(&mut rand::thread_rng()), G1Affine::random(&mut rand::thread_rng())],
        };
        let alpha1_assigned = pairing_chip.load_private_g1_unchecked(builder.main(0), verif_key.alpha1);
        let beta2_assigned = pairing_chip.load_private_g2_unchecked(builder.main(0), verif_key.beta2);
        let gamma2_assigned = pairing_chip.load_private_g2_unchecked(builder.main(0), verif_key.gamma2);
        let delta2_assigned = pairing_chip.load_private_g2_unchecked(builder.main(0), verif_key.delta2);
        let ic_assigned = verif_key.ic.iter().map(|ic| pairing_chip.load_private_g1_unchecked(builder.main(0), *ic)).collect::<Vec<_>>();

        // println!("ic_assigned: {:?}", ic_assigned);

        // // let dummy_proof = get_dummy_proof();
        let dummy_proof = Proof {
            a: G1Affine::random(&mut rand::thread_rng()),
            b: G2Affine::random(&mut rand::thread_rng()),
            c: G1Affine::random(&mut rand::thread_rng()),
            //TODO change to Fr
            public_inputs: vec![20]
        };
        let a_assigned = pairing_chip.load_private_g1_unchecked(builder.main(0), dummy_proof.a);
        let b_assigned = pairing_chip.load_private_g2_unchecked(builder.main(0), dummy_proof.b);
        let c_assigned = pairing_chip.load_private_g1_unchecked(builder.main(0), dummy_proof.c);
        let public_inputs = dummy_proof.public_inputs;

        // // let 
        let fp2_chip = Fp2Chip::<bn256::Fr>::new(fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        let g1_zero_point = G1Affine::generator().mul(bn256::Fr::zero()).to_affine();
        let vk_x = pairing_chip.load_private_g1_unchecked(builder.main(0), g1_zero_point);

        for i in 0..public_inputs.len() {
            //TODO assert
            let (x,y) = (&ic_assigned[i+1].x, &ic_assigned[i+1].y);

            let x_ic_mul_input = 
                g2_chip.field_chip.fp_chip().scalar_mul_no_carry(builder.main(0), x, public_inputs[i] as i64);

            let y_ic_mul_input = 
                g2_chip.field_chip.fp_chip().scalar_mul_no_carry(builder.main(0), y, public_inputs[i] as i64);

            let x_ic_mul_input_add_vk_x = 
                g2_chip.field_chip.fp_chip().scalar_mul_and_add_no_carry(builder.main(0), x, vk_x , public_inputs[i] as i64);

            // g2_chip.field_chip.fp_chip().add_no_carry(builder.main(0), vk_x, x_ic_mul_input);
        }

        // let Q = G2Affine::random(&mut rand::thread_rng());
        // let P_assigned = pairing_chip.load_private_g1_unchecked(builder.main(0), P);
        // let Q_assigned = pairing_chip.load_private_g2_unchecked(builder.main(0), Q);
        // pairing_chip.pairing(builder.main(0), &Q_assigned, &P_assigned);
        Ok(())
    }
}

pub trait AppCircuit<F: BigPrimeField> {
    fn create_circuit(
        stage: CircuitBuilderStage,
        params: PairingCircuitParams,
        P: G1Affine,
        Q: G2Affine,
    ) -> Result<BaseCircuitBuilder<bn256::Fr>, Error>;
}

impl <F: BigPrimeField> AppCircuit<F> for TestCircuit<F> {
    fn create_circuit(
        stage: CircuitBuilderStage,
        params: PairingCircuitParams,
        P: G1Affine,
        Q: G2Affine,
    ) -> Result<BaseCircuitBuilder<bn256::Fr>, Error> {

        let k = params.degree as usize;

        let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_k(params.degree as usize);
        // builder.use_k(params.degree as usize);
        // builder.set_lookup_bits(params.lookup_bits);
        // MockProver::run(9, &builder, vec![]).unwrap().assert_satisfied();
        // if let Some(lb) = params.lookup_bits {
            // builder.set_lookup_bits(params.lookup_bits);
        // }
        let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());

        let ctx = builder.main(0);
        // // run the function, mutating `builder`

        let fp_chip = FpChip::new(&range, params.limb_bits, params.num_limbs);
        let res1 = Self::synthesize(&mut builder, &fp_chip);
        // let res = pairing_test(ctx, &range, params, P, Q);

        // // helper check: if your function didn't use lookups, turn lookup table "off"
        let t_cells_lookup =
            builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
        let lookup_bits = if t_cells_lookup == 0 { None } else { std::option::Option::Some(params.lookup_bits) };
        builder.set_lookup_bits(params.lookup_bits);

        // // // configure the circuit shape, 9 blinding rows seems enough
        builder.calculate_params(Some(9));
        
        


        Ok((builder))
        
    }
}



#[test]


fn test_pairing_circuit() {

    let path = "/Users/rishabh/projects/blockchain/avail-project/halo2-aggregation/src/configs/bn254/pairing_circuit.config";
    let params: PairingCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let P = G1Affine::random(&mut rng);
    let Q = G2Affine::random(&mut rng);
    let circuit = TestCircuit::<Fr>::create_circuit(
        CircuitBuilderStage::Mock,
        params, 
        P, 
        Q).unwrap();
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
    
    // let prover = MockProver::<Fr>::run(9, &circuit, vec![]).unwrap();
}

fn test_pairing() {
    
    let path = "/Users/rishabh/projects/blockchain/avail-project/halo2-aggregation/src/configs/bn254/pairing_circuit.config";
    let params: PairingCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let P = G1Affine::random(&mut rng);
    let Q = G2Affine::random(&mut rng);
    // base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
    //     pairing_test(ctx, range, params, P, Q);
    // });


    let mut stage = CircuitBuilderStage::Mock;

    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_k(params.degree as usize);
    // builder.use_k(params.degree as usize);
    // builder.set_lookup_bits(params.lookup_bits);
    // MockProver::run(9, &builder, vec![]).unwrap().assert_satisfied();
    // if let Some(lb) = params.lookup_bits {
        // builder.set_lookup_bits(params.lookup_bits);
    // }
    let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());

    let ctx = builder.main(0);
    // // run the function, mutating `builder`

    let res = pairing_test(ctx, &range, params, P, Q);

    // // helper check: if your function didn't use lookups, turn lookup table "off"
    let t_cells_lookup =
        builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
    let lookup_bits = if t_cells_lookup == 0 { None } else { std::option::Option::Some(params.lookup_bits) };
    builder.set_lookup_bits(params.lookup_bits);

    // // // configure the circuit shape, 9 blinding rows seems enough
    builder.calculate_params(Some(9));
    MockProver::run(params.degree, &builder, vec![]).unwrap().assert_satisfied();
}



fn main(){
    println!("Hello, world!");
}