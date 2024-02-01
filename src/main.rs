use manifest_producer::elf_analysis;
mod error;

fn main() {
    let elf_file_path = "./binaries/debug-info/fake-firmware-c";
    //let elf_file_path = "./binaries/stripped/fake-firmware-c";

    match elf_analysis(elf_file_path) {
        Ok(_elf) => {

        }
        Err(error) => {
            eprintln!("Error: {}", error);
        }
    }
}

