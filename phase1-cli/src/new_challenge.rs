use phase1::{Phase1, Phase1Parameters};
use setup_utils::{calculate_hash, print_hash, UseCompression};

use algebra::PairingEngine as Engine;

use std::{io::Write};
use tracing::info;

use std::fs::File;
use std::io::{Read, BufWriter};

const COMPRESS_NEW_CHALLENGE: UseCompression = UseCompression::No;

pub fn new_challenge<T: Engine + Sync>(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    parameters: &Phase1Parameters<T>,
) {
    info!(
        "Will generate an empty accumulator for 2^{} powers of tau",
        parameters.total_size_in_log2
    );
    info!("In total will generate up to {} powers", parameters.powers_g1_length);

    let expected_challenge_length = match COMPRESS_NEW_CHALLENGE {
        UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
        UseCompression::No => parameters.accumulator_size,
    };

    let mut buffer = vec![0; expected_challenge_length];
    
    Phase1::initialization(&mut buffer, COMPRESS_NEW_CHALLENGE, &parameters)
        .expect("generation of initial accumulator is successful");
    
    let mut file = BufWriter::new(File::create(challenge_filename).expect("unable to create challenge file"));
    file.write_all(&buffer).expect("unable to write buffer to challenge file");
    file.flush().expect("unable to flush buffer to challenge file");

    let mut file = File::open(challenge_filename).expect("unable to open challenge file for hashing");
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).expect("unable to read challenge file");
    let contribution_hash = calculate_hash(&file_contents);

    std::fs::File::create(challenge_hash_filename)
        .expect("unable to open new challenge hash file")
        .write_all(contribution_hash.as_slice())
        .expect("unable to write new challenge hash");

    info!("Empty contribution is formed with a hash:");
    print_hash(&contribution_hash);
    info!("Wrote a fresh accumulator to challenge file");
}
