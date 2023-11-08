use phase1::{Phase1, Phase1Parameters};
use setup_utils::{calculate_hash, print_hash, BatchExpMode, CheckForCorrectness, UseCompression};

use algebra::PairingEngine as Engine;

use memmap::*;
use rand::Rng;
use std::{
    fs::{OpenOptions},
    io::{Read, Write, BufWriter},
    
};
use std::fs::File;
use tracing::info;

const COMPRESSED_INPUT: UseCompression = UseCompression::No;
const COMPRESSED_OUTPUT: UseCompression = UseCompression::Yes;

pub fn contribute<T: Engine + Sync>(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    response_filename: &str,
    response_hash_filename: &str,
    check_input_correctness: CheckForCorrectness,
    batch_exp_mode: BatchExpMode,
    parameters: &Phase1Parameters<T>,
    mut rng: impl Rng,
) {
    // Try to load challenge file from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open(challenge_filename)
        .expect("unable open challenge file");
    
        let metadata = reader
            .metadata()
            .expect("unable to get filesystem metadata for challenge file");
        let expected_challenge_length = match COMPRESSED_INPUT {
            UseCompression::Yes => parameters.contribution_size,
            UseCompression::No => parameters.accumulator_size,
        };

        if metadata.len() != (expected_challenge_length as u64) {
            panic!(
                "The size of challenge file should be {}, but it's {}, so something isn't right.",
                expected_challenge_length,
                metadata.len()
            );
        }
    

    let readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    let required_output_length = match COMPRESSED_OUTPUT {
        UseCompression::Yes => parameters.contribution_size,
        UseCompression::No => parameters.accumulator_size + parameters.public_key_size,
    };

    let mut writable_map = vec![0; required_output_length];

    info!("Calculating previous contribution hash...");

    assert!(
        UseCompression::No == COMPRESSED_INPUT,
        "Hashing the compressed file in not yet defined"
    );
    let current_accumulator_hash = calculate_hash(&readable_map);


    info!("`challenge` file contains decompressed points and has a hash:");
        print_hash(&current_accumulator_hash);
        std::fs::File::create(challenge_hash_filename)
            .expect("unable to open current accumulator hash file")
            .write_all(current_accumulator_hash.as_slice())
            .expect("unable to write current accumulator hash");

    writable_map[..current_accumulator_hash.len()]
        .copy_from_slice(current_accumulator_hash.as_slice());


    // Construct our keypair using the RNG we created above
    let (public_key, private_key) =
        Phase1::key_generation(&mut rng, current_accumulator_hash.as_ref()).expect("could not generate keypair");

    // Perform the transformation
    info!("Computing and writing your contribution, this could take a while...");

    // this computes a transformation and writes it
    Phase1::computation(
        &readable_map,
        &mut writable_map,
        COMPRESSED_INPUT,
        COMPRESSED_OUTPUT,
        check_input_correctness,
        batch_exp_mode,
        &private_key,
        &parameters,
    )
    .expect("must contribute with the key");

    info!("Finishing writing your contribution to response file...");

    // Write the public key
    public_key
        .write(&mut writable_map, COMPRESSED_OUTPUT, &parameters)
        .expect("unable to write public key");

    let mut file = BufWriter::new(File::create(response_filename).expect("unable to create challenge file"));
    file.write_all(&writable_map).expect("unable to write buffer to challenge file");
    file.flush().expect("unable to flush buffer to challenge file");

    // Get the hash of the contribution, so the user can compare later
    let mut file = File::open(response_filename).expect("unable to open challenge file for hashing");
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).expect("unable to read challenge file");
    let contribution_hash = calculate_hash(&file_contents);

    info!(
        "Done!\n\n\
              Your contribution has been written to response file\n\n\
              The BLAKE2b hash of response file is:\n"
    );
    print_hash(&contribution_hash);
    std::fs::File::create(response_hash_filename)
        .expect("unable to open contribution hash file")
        .write_all(contribution_hash.as_slice())
        .expect("unable to write contribution hash");
    info!("Thank you for your participation, much appreciated! :)");
}
