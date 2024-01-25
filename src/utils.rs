// EcPoint<F, FqPoint<F>>
use std::{
    fs::{self, File}, io::{BufRead, BufReader}, marker::PhantomData
};

// use super::*;
use halo2_ecc::{
    bn254::{self, pairing::{PairingChip}, Fp12Chip, FpChip, FpPoint, FqPoint}, ecc::EcPoint, fields::FieldChip, halo2_base};
use halo2_ecc::{
    // fields::FpStrategy
    fields::FpStrategy, 
    // halo2_proofs::halo2curves::bn256::G2Affine
};

use ark_ff::{MontFp, QuadExtConfig, Fp};


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
                pairing, Fq2, G1Affine, G2Affine
            }, grumpkin::{Fq, Fr}
        }, plonk::{
            Selector, Advice
        }, poly::commitment::Prover
    },
    halo2_proofs::halo2curves::bn256::{self}
};

// use halo2curves::bn256::Fr;
// use halo2curves::bn256::pairing;
use rand::rngs::StdRng;
use rand_core::{Error, SeedableRng};
use serde::{Deserialize, Serialize};



pub struct VerificationKey {
    pub alpha1: G1Affine,
    pub beta2: G2Affine,
    pub gamma2: G2Affine,
    pub delta2: G2Affine,
    pub ic: Vec<G1Affine>,

}

pub struct VerificationKeyTarget <F: BigPrimeField> {
    pub alpha1: EcPoint<F, FqPoint<F>>,
    pub beta2: EcPoint<F, FpPoint<F>>,
    pub gamma2: EcPoint<F, FpPoint<F>>,
    pub delta2: EcPoint<F, FpPoint<F>>,
    pub ic: Vec<EcPoint<F, FqPoint<F>>>,

}

pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
    pub public_inputs: Vec<Fq>
}


// pub fn get_dummy_proof() -> Proof {
//     Proof {
//         a: G1Affine::from(
//             Fq::from(MontFp!("12887163950774589848429612384269252267879103641214292968732875014481055665029")),
//             Fq::from(MontFp!("21622722808554299809135926587843590844306004439941801858752721909447067565676")),
//         ),
//         b: G2Affine::new(
//             Fq2::new(
//                 MontFp!("19252399014017622041717411504172796635144662505041726695471440307521907621323"),
//                 MontFp!("11302764088468560462334032644947221757922107890363805071604206102241252698616"),
//             ),
//             Fq2::new(
//                 MontFp!("226455389767104611295930017850538586277567900474601688185243021343711813551"),
//                 MontFp!("18768786825809469978354139019891648686066930676359588724933329715343055477839"),
//             ),
//         ),
//         c: G1Affine::new(
//             Fq::from(MontFp!("16716067220884575876883941674457042090348240918922797664931133638121340220774")),
//             Fq::from(MontFp!("19465170897811434280250972276398658394224541760713812318242639282725837098749")),
//         ),
//         public_inputs: vec![Fq::from(20)]
//     }
// }


// pub fn get_verification_key() -> VerificationKey {
//     VerificationKey {
//         alpha1: G1Affine::new(
//             Fq::from(MontFp!("6763126530687886999315782887200758703366235230289874831627658839515656330867")),
//             Fq::from(MontFp!("12297948670392550312636836114470404429657568989657927437959695771502446445179")),
//         ),
//         beta2: G2Affine::new(
//             Fq2::new(
//                 MontFp!("15362786867599176251482538547160991918100063526460909721657878971551583339657"),

//                 MontFp!("3804423004921008809819632629079723167970572551072432396497601916259815496626"),

//             ),
//             Fq2::new(
//                 MontFp!("21885719103633717693283841528133243510750001708857084897139570082577218850374"),

//                 MontFp!("2076817281717432063622727433912740683541778328445173073030513609350245776784"),

//             ),
//         ),
//         gamma2: G2Affine::new(
//             Fq2::new(
//                 MontFp!("1505558511994093266228972967760414664043255115544025409518939393775943607863"),

//                 MontFp!("21131173266568468249589649137903719095480044620502529067534622738225157042304"),

//             ),
//             Fq2::new(
//                 MontFp!("4008759115482693545406793535591568078300615151288108694080317738431649117177"),

//                 MontFp!("18835856718271757625037377080288624550370480296914695806777038708085497610013"),

//             ),
//         ),
//         delta2: G2Affine::new(
//             Fq2::new(
//                 MontFp!("1497911744463986566314308077983046202449361313910668647770797503379177516252"),

//                 MontFp!("10829154948357654897792444316512827659620136273388886760324770466776134105520"),

//             ),
//             Fq2::new(
//                 MontFp!("10850392992008761830625471778404650447428083833210258292805429019728339148884"),

//                 MontFp!("12593805385728178657844996215584371401133999503150901444097670307277076679963"),

//             ),
//         ),
//         ic: vec![
//             G1Affine::new(
//                 Fq::from(MontFp!("20417302999686518463947604254824206482787540497747166602791183033521164889663")),
//                 Fq::from(MontFp!("13070739245581256634078674103787887995405997871287223137308760941168103411852")),
//             ),
//             G1Affine::new(
//                 Fq::from(MontFp!("7134628694475811382742267026042639323743922548568185680200196927023443639137")),
//                 Fq::from(MontFp!("9624761392337090719715532152667200620426657721236517270124636244477804835035")),
//             ),
//         ],
//     }
// }