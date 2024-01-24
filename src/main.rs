use std::{
    fs::{self, File}, io::{BufRead, BufReader}, marker::PhantomData
};

// use super::*;
use halo2_ecc::{fields::FieldChip, halo2_base};
use halo2_ecc::{
    // fields::FpStrategy
    fields::FpStrategy, 
    // halo2_proofs::halo2curves::bn256::G2Affine
};

use halo2_base::{
    gates::{
        circuit::{
            builder::{self, BaseCircuitBuilder, RangeCircuitBuilder}, CircuitBuilderStage}, RangeChip}, utils::{BigPrimeField, testing::gen_proof}, Context, halo2_proofs::{dev::{metadata::Column, MockProver}, plonk::{Selector, Advice}}};
use rand_core::Error;

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

// fn pairing_test<F: BigPrimeField>(
//     ctx: &mut Context<F>,
//     range: &RangeChip<F>,
//     params: PairingCircuitParams,
//     P: G1Affine,
//     Q: G2Affine,
// ) {
//     let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
//     let chip = PairingChip::new(&fp_chip);
//     let P_assigned = chip.load_private_g1(ctx, P);
//     let Q_assigned = chip.load_private_g2(ctx, Q);
//     // test optimal ate pairing
//     let f = chip.pairing(ctx, &Q_assigned, &P_assigned);
//     let actual_f = pairing(&P, &Q);
//     let fp12_chip = Fp12Chip::new(&fp_chip);
//     // cannot directly compare f and actual_f because `Gt` has private field `Fq12`
//     assert_eq!(
//         format!("Gt({:?})", fp12_chip.get_assigned_value(&f.into())),
//         format!("{actual_f:?}")
//     );
// }


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
        builder:&mut BaseCircuitBuilder<F>,
        fp_chip: &FpChip<F>,
    ) -> Result<(), Error> {
        let pairing_chip = PairingChip::new(fp_chip);
        let P = G1Affine::random(&mut rand::thread_rng());
        let Q = G2Affine::random(&mut rand::thread_rng());
        let P_assigned = pairing_chip.load_private_g1(builder.main(0), P);
        let Q_assigned = pairing_chip.load_private_g2(builder.main(0), Q);
        pairing_chip.pairing(builder.main(0), &Q_assigned, &P_assigned);
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use std::path;
    use halo2_base::gates::circuit::CircuitBuilderStage;

    use super::*;
    use crate::bn254::tests::pairing::PairingCircuitParams;

    
    #[test]
    fn test_pp() {
        const K: u32 = 9;
        // let params: ParamsKZG
        let path = "configs/bn254/pairing_circuit.config";
        let params: PairingCircuitParams = serde_json::from_reader(
            File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
        )
        .unwrap();
        let lookup_bits = params.lookup_bits;
        let mut stage = CircuitBuilderStage::Mock;
        let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage)
            .use_k(K as usize)
            .set_lookup_bits(lookup_bits);
        // let range
        }
}

#[test]
fn test_pairing() {
    let path = "configs/bn254/pairing_circuit.config";
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

#[test]
fn bench_pairing() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_pairing.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bn254/pairing_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,proof_time,proof_size,verify_time")?;

    let mut rng = StdRng::seed_from_u64(0);
    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: PairingCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let P = G1Affine::random(&mut rng);
        let Q = G2Affine::random(&mut rng);
        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (P, Q),
            (P, Q),
            |pool, range, (P, Q)| {
                pairing_test(pool.main(), range, bench_params, P, Q);
            },
        );

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            stats.proof_time.time.elapsed(),
            stats.proof_size,
            stats.verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
