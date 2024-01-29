use std::{
    fs::{self, File}, io::{BufRead, BufReader}, marker::PhantomData, ops::{Add, Mul, Neg}
};

use ark_ff::{fp, fp2, BigInt, BigInteger};
// use super::*;
use halo2_ecc::{
    bigint::{self, big_is_zero::crt, check_carry_mod_to_zero, ProperCrtUint}, bn254::{self, pairing::{PairingChip}, Fp12Chip, Fp2Chip, FpChip}, ecc::{self, EcPoint, EccChip}, fields::FieldChip, halo2_base};
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
        testing::gen_proof, BigPrimeField, ScalarField
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
use num_bigint::U64Digits;
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
        let ctx = builder.main(0);
        let pairing_chip = PairingChip::new(fp_chip);
        // let verif_key = get_verification_key();
        let verif_key = get_verification_key();
        let alpha1_assigned = pairing_chip.load_private_g1_unchecked(ctx, verif_key.alpha1);
        let beta2_assigned = pairing_chip.load_private_g2_unchecked(ctx, verif_key.beta2);
        let gamma2_assigned = pairing_chip.load_private_g2_unchecked(ctx, verif_key.gamma2);
        let delta2_assigned = pairing_chip.load_private_g2_unchecked(ctx, verif_key.delta2);
        let ic_assigned = verif_key.ic.iter().map(|ic| pairing_chip.load_private_g1_unchecked(ctx, *ic)).collect::<Vec<_>>();

        // println!("ic_assigned: {:?}", ic_assigned);

        // // let dummy_proof = get_dummy_proof();
        let dummy_proof = get_dummy_proof();

        //declare our chips for performing the ecc operations
        let fp2_chip = Fp2Chip::<bn256::Fr>::new(fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        //extract the points of proof and public inputs
        let a_neg = dummy_proof.a.neg();
        let neg_a_assigned = pairing_chip.load_private_g1_unchecked(ctx, a_neg);
        // let a_assigned_into = a_assigned.into();
        
        // let neg_a_assigned = EcPoint::new(a_assigned_into.x, fp_chip.negate(ctx, a_assigned_into.y));
        // let neg_a_assigned = g2_chip.negate(ctx, &a_assigned);

        // let neg_a_assigned = fp_chip.negate(ctx, &a_assigned);
        let b_assigned = pairing_chip.load_private_g2_unchecked(ctx, dummy_proof.b);
        let c_assigned = pairing_chip.load_private_g1_unchecked(ctx, dummy_proof.c);
        let public_inputs = dummy_proof.public_inputs;

        // Implement vk_x = vk.ic[0];
        let vk_x_assigned = &ic_assigned[0];
        let mut vk_xx = vk_x_assigned.x.clone();
        let mut vk_xy = vk_x_assigned.y.clone();
        println!("init vk_xx {:?}", &vk_xx.value());

        let ic_0 = pairing_chip.load_private_g1_unchecked(ctx, verif_key.ic[0]);
        let ic_1 = pairing_chip.load_private_g1_unchecked(ctx, verif_key.ic[1]);

        for i in 0..public_inputs.len() {
            //TODO assert
            let (x,y) = (&ic_assigned[i+1].x, &ic_assigned[i+1].y);


            {//a different aaproach
                
                let con = fp_chip.load_constant(ctx,  bn256::Fq::from_u64_digits(&[public_inputs[i]]));
                let con2 = fp_chip.load_constant(ctx,  bn256::Fq::from_u64_digits(&[public_inputs[i]]));
                let d_vk_xx = ic_0.x.clone();
                let d_vk_xy = ic_0.y.clone();
                let (d_x, d_y) = (&ic_1.x, &ic_1.y);
                
                let x_ic_mul_input = fp_chip.mul_no_carry (ctx, d_x, con);
                let y_ic_mul_input = fp_chip.mul_no_carry (ctx, d_y, con2);
                // let x_ic_mul_input = fp_chip.scalar_mul_no_carry(ctx, d_x, 20);
                let x_ic_mul_input_add_vk_xx = fp_chip.add_no_carry(ctx, x_ic_mul_input, d_vk_xx );
                let x_ic_mul_input_add_vk_xx_carry = fp_chip.carry_mod(ctx, x_ic_mul_input_add_vk_xx);

                let y_ic_mul_input_add_vk_xy = fp_chip.add_no_carry(ctx, y_ic_mul_input, d_vk_xy );
                let y_ic_mul_input_add_vk_xy_carry = fp_chip.carry_mod(ctx, y_ic_mul_input_add_vk_xy);
                println!("x_ic_mul_input_add_vk_xx_carry {:?}", &x_ic_mul_input_add_vk_xx_carry.value());

                let d_vk_x_affine= G1Affine{
                    x: bn256::Fq::from_u64_digits(&x_ic_mul_input_add_vk_xx_carry.value().to_u64_digits()),
                    y: bn256::Fq::from_u64_digits(&y_ic_mul_input_add_vk_xy_carry.value().to_u64_digits()),
                };
                println!("d_vk_x_affine {:?}", &d_vk_x_affine);
            }

            let x_ic_mul_input_add_vk_x = 
                g2_chip.field_chip.fp_chip().scalar_mul_and_add_no_carry(ctx, x, vk_xx , public_inputs[i] as i64);
            println!("x_ic_mul_input_add_vk_x {:?}", &x_ic_mul_input_add_vk_x.value);
            

            let y_ic_mul_input_add_vk_y = 
                g2_chip.field_chip.fp_chip().scalar_mul_and_add_no_carry(ctx, y, vk_xy , public_inputs[i] as i64);

            //TODO converting CRTInt to ProperCRTUint
            vk_xx = fp_chip.carry_mod(ctx, x_ic_mul_input_add_vk_x);

            println!("vk_xx {:?}", &vk_xx.value());
            // 9892176786327819563068104558876067336791813368026114567971856311473454212322     vk_xx
            // 163109876889202746118792944775676992957665991469110880206795121573990037672403   x_ic_mul_input_add_vk_x
            // 13251968311295594469648996761684988829700683503300492965985404526851470980489    correct val
            
            vk_xy = fp_chip.carry_mod(ctx, y_ic_mul_input_add_vk_y);
        }

        // let vk_xx_add_ic_zero_x = fp_chip.add_no_carry(ctx, vk_xx, &ic_assigned[0].x);
        // let vk_xy_add_ic_zero_y = fp_chip.add_no_carry(ctx, vk_xy, &ic_assigned[0].y);

        // vk_xx = fp_chip.carry_mod(ctx, vk_xx_add_ic_zero_x);
        println!("final vk_xx {:?}", &vk_xx.value());

        // vk_xy = fp_chip.carry_mod(ctx, vk_xy_add_ic_zero_y);

        //TODO a_neg should be in circuit
        let vk_x_affine= G1Affine{
            x: bn256::Fq::from_u64_digits(&vk_xx.value().to_u64_digits()),
            y: bn256::Fq::from_u64_digits(&vk_xy.value().to_u64_digits()),
        };

        
        {
            //Sanity check
            let mut vk_x = verif_key.ic[0];
            let l = public_inputs.len();
            for i in 0..l {
                //TODO
                // assert!(input[i] < )
                vk_x =  (verif_key.ic[i+1].mul( bn256::Fr::from_u64_digits(&[public_inputs[i]]))).add(vk_x).to_affine();
            }

            println!("vk_x {:?}", vk_x);

            // assert_eq!(
            //     format!("vk_x_assigned {:?}", fp_chip.get_assigned_value(&vk_x_assigned)),
            //     format!("vk_xdsdqw {:?}", vk_xdsdqw)
            // )

        }
        
        // let p1 = pairing_chip.pairing(ctx, &b_assigned, &neg_a_assigned);
        // let p2 = pairing_chip.pairing(ctx, &beta2_assigned, &alpha1_assigned);
        // let p3 = pairing_chip.pairing(ctx, &gamma2_assigned, &vk_x_assigned);
        // let p4 = pairing_chip.pairing(ctx, &delta2_assigned, &c_assigned);


        // let fp12_chip = Fp12Chip::<bn256::Fr>::new(fp_chip);

        // let p1_p2 = fp12_chip.mul(ctx, &p1, &p2);

        // let p3_p4 = fp12_chip.mul(ctx, &p3, &p4);

        // let p1_p2_p3_p4 = fp12_chip.mul(ctx, &p1_p2, &p3_p4);



        // let Q = G2Affine::random(&mut rand::thread_rng());
        // let P_assigned = pairing_chip.load_private_g1_unchecked(ctx, P);
        // let Q_assigned = pairing_chip.load_private_g2_unchecked(ctx, Q);
        // pairing_chip.pairing(ctx, &Q_assigned, &P_assigned);
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