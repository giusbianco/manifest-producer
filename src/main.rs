use manifest_producer::{elf_analysis_with_mapping, elf_analysis_with_strace};
mod error;

fn main() {
    let elf_file_path = "binaries/stripped/fake-firmware-c";

    match elf_analysis_with_mapping(elf_file_path) {
        Ok(_) => {
            println!("Elf analysis succeded, using syscall mapping for job2.");
        }
        Err(error) => {
            eprintln!("Elf analysis failed: {}", error);
        }
    }

    match elf_analysis_with_strace(elf_file_path) {
        Ok(_) => {
            println!("Elf analysis succeded, using strace for job2.");
        }
        Err(error) => {
            eprintln!("Elf analysis failed: {}", error);
        }
    }
}
