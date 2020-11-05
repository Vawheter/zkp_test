#![allow(non_snake_case)]

extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};

use std::time::{Duration, Instant};

const MIMC_ROUNDS: usize = 5;
const SAMPLES: usize = 16380; //1048576//131070;//1048570;//131070;//16380;//16380;//16384


fn mimc (mut xl: Scalar, mut xr: Scalar, constants: &[Scalar]) -> Scalar {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    for i in 0..MIMC_ROUNDS {
        let mut xl_c = xl + constants[i];
        let xl_c_square = xl_c * xl_c;
        let xl_c_cube_xr = xl_c_square * xl_c + xr;
        xr = xl;
        xl = xl_c_cube_xr;
    }

    xl
}

fn mimc_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    xl_value: Scalar,
    xr_value: Scalar,
    constants: &[Scalar],
) {
    let hash_value = mimc(xl_value, xr_value, constants);
    let mut xl: LinearCombination = xl_value.into();
    let mut xr: LinearCombination = xr_value.into();

    for i in 0..MIMC_ROUNDS { 
        let c: LinearCombination = constants[i].into();
        let xl_c: LinearCombination = xl.clone() + c;
        let (_, _, xl_c_square) = cs.multiply(xl_c.clone(), xl_c.clone());
        let (_, _, xl_c_cube) = cs.multiply(xl_c, xl_c_square.into());

        let xl_c_cube_xr: LinearCombination = xl_c_cube + xr;
        xr = xl;
        xl = xl_c_cube_xr;
    }
    let hash: LinearCombination = hash_value.into();
    cs.constrain(xl - hash);
}


#[test]
fn mimc_gadget_test() {

    let mut crs_time = Duration::new(0, 0);
    let mut prove_time = Duration::new(0, 0);
    let mut verify_time = Duration::new(0, 0);
    
    let start = Instant::now();
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(2<<17, 1);
    crs_time += start.elapsed();

    let crs_time = crs_time.subsec_nanos() as f64 / 1_000_000_000f64 + (crs_time.as_secs() as f64);
    println!("{:?}", crs_time);

    let constants = (0..MIMC_ROUNDS).map(|_| Scalar::random(&mut thread_rng()) ).collect::<Vec<_>>();

    let mut p_transcript = Transcript::new(b"MiMC_Gadget");
    let mut prover = Prover::new(&pc_gens, &mut p_transcript);

    let mut v_transcript = Transcript::new(b"MiMC_Gadget");
    let mut verifier = Verifier::new(&mut v_transcript);

    for i in 0..SAMPLES {
        let xl = Scalar::random(&mut thread_rng());
        let xr = Scalar::random(&mut thread_rng());
        mimc_gadget(&mut prover, xl, xr, &constants);
        mimc_gadget(&mut verifier, xl, xr, &constants);
    }
    
    let start = Instant::now();
    let proof = prover.prove(&bp_gens).unwrap();
    prove_time += start.elapsed();

    let start = Instant::now();
    verifier
        .verify(&proof, &pc_gens, &bp_gens)
        .map_err(|_| R1CSError::VerificationError);
    verify_time += start.elapsed();

    let prove_time =
        prove_time.subsec_nanos() as f64 / 1_000_000_000f64 + (prove_time.as_secs() as f64);
    let verify_time =
        verify_time.subsec_nanos() as f64 / 1_000_000_000f64 + (verify_time.as_secs() as f64);
    
    println!("{:?}", prove_time);
    println!("{:?}", verify_time);
}