use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{rand::rngs::StdRng, UniformRand};
use ark_crypto_primitives::snark::SNARK;
use ark_std::rand::SeedableRng;

// Define our circuit for the square relation
// We want to prove knowledge of x such that x^2 = y
#[derive(Clone)]
struct SquareCircuit {
    // The number we want to prove we know
    x: Option<Fr>,
    // The square of x
    y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate the first witness value (x)
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocate the public input value (y)
        let y = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;

        // Enforce that x * x = y
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + y)?;

        Ok(())
    }
}

fn main() {
    // Create a random number
    let mut rng = StdRng::seed_from_u64(0u64);
    let x = Fr::rand(&mut rng);
    let y = x * x;

    // Create an instance of our circuit
    let circuit = SquareCircuit {
        x: Some(x),
        y: Some(y),
    };

    // Generate the proving and verifying keys
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

    // Create the proof
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    // Prepare the verification key
    let pvk = prepare_verifying_key(&vk);

    // Verify the proof
    let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[y], &proof).unwrap();

    println!("Proof verification result: {}", result);
    println!("Original number: {}", x);
    println!("Square: {}", y);
} 