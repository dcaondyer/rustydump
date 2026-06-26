use colored::Colorize;

struct Pattern<'a> {
    label: &'a str,
    needle: &'a str,
    weight: u32,
}

struct CompilerSignature<'a> {
    name: &'a str,
    patterns: &'a [Pattern<'a>], // (label, needle)
}

struct CompilerMatch {
    name: String,
    score: u32,
    hits: Vec<(String, String)>,
}

fn compiler_db() -> Vec<CompilerSignature<'static>> {
    vec![
        CompilerSignature {
            name: "gcc",
            patterns: &[
                Pattern {
                    label: "version",
                    needle: "GCC:",
                    weight: 50,
                },
                Pattern {
                    label: "compiler",
                    needle: "GNU C",
                    weight: 30,
                },
            ],
        },
        CompilerSignature {
            name: "g++",
            patterns: &[
                Pattern {
                    label: "version",
                    needle: "G++",
                    weight: 40,
                },
                Pattern {
                    label: "stdlib",
                    needle: "libstdc++",
                    weight: 35,
                },
            ],
        },
        CompilerSignature {
            name: "clang",
            patterns: &[
                Pattern {
                    label: "version",
                    needle: "clang version",
                    weight: 50,
                },
                Pattern {
                    label: "backend",
                    needle: "LLVM",
                    weight: 25,
                },
            ],
        },
        CompilerSignature {
            name: "clang++",
            patterns: &[
                Pattern {
                    label: "version",
                    needle: "clang version",
                    weight: 45,
                },
                Pattern {
                    label: "stdlib",
                    needle: "libc++",
                    weight: 35,
                },
            ],
        },
        CompilerSignature {
            name: "msvc",
            patterns: &[
                Pattern {
                    label: "compiler",
                    needle: "MSVC",
                    weight: 60,
                },
                Pattern {
                    label: "toolchain",
                    needle: "Microsoft (R) C/C++",
                    weight: 70,
                },
            ],
        },
        CompilerSignature {
            name: "rust",
            patterns: &[
                Pattern {
                    label: "version",
                    needle: "rustc ",
                    weight: 60,
                },
                Pattern {
                    label: "edition",
                    needle: "rust edition",
                    weight: 30,
                },
            ],
        },
        CompilerSignature {
            name: "go",
            patterns: &[
                Pattern {
                    label: "version",
                    needle: "go1.",
                    weight: 60,
                },
                Pattern {
                    label: "build",
                    needle: "Go build ID",
                    weight: 40,
                },
            ],
        },
    ]
}

fn scan_compiler_score(bytes: &[u8], sig: &CompilerSignature) -> (u32, Vec<(String, String)>) {
    let mut score = 0;
    let mut hits = Vec::new();

    for p in sig.patterns {
        if let Some(value) = find_string_in_bytes(bytes, p.needle.as_bytes()) {
            score += p.weight;
            hits.push((p.label.to_string(), value));
        }
    }

    (score, hits)
}

/*
fn detect_best_compiler(bytes: &[u8]) -> Option<(String, u32, Vec<(String, String)>)> {
    let mut best: Option<(String, u32, Vec<(String, String)>)> = None;

    for sig in compiler_db() {
        let (score, hits) = scan_compiler_score(bytes, &sig);

        if score == 0 {
            continue;
        }

        match &best {
            None => {
                best = Some((sig.name.to_string(), score, hits));
            }
            Some((_, best_score, _)) if score > *best_score => {
                best = Some((sig.name.to_string(), score, hits));
            }
            _ => {}
        }
    }

    best
}
*/

fn detect_compilers_ranked(bytes: &[u8]) -> Vec<CompilerMatch> {
    let mut results = Vec::new();

    for sig in compiler_db() {
        let (score, hits) = scan_compiler_score(bytes, &sig);

        if score > 0 {
            results.push(CompilerMatch {
                name: sig.name.to_string(),
                score,
                hits,
            });
        }
    }

    // Ordina per score decrescente
    results.sort_by(|a, b| b.score.cmp(&a.score));

    results
}

fn find_string_in_bytes(bytes: &[u8], needle: &[u8]) -> Option<String> {
    bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .and_then(|pos| {
            // Leggi fino al prossimo null byte o carattere non ASCII
            let start = pos + needle.len();
            let end = bytes[start..]
                .iter()
                .position(|&b| b == 0 || b > 127)
                .map(|e| start + e)
                .unwrap_or(start + 32);
            std::str::from_utf8(&bytes[start..end.min(start + 64)])
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

pub fn print_compiler_info(bytes: &[u8]) {
    let compilers = detect_compilers_ranked(bytes);

    if compilers.is_empty() {
        println!("{} {}", "; No compiler detected".bright_black(), "");
        println!("{}", ";".bright_black());
        return;
    }

    println!(
        "{}",
        "; Detected compilers (ranked by score):".bright_black()
    );

    for c in &compilers {
        println!(
            "{} {} {}",
            ";".bright_black(),
            c.name.bright_white(),
            format!("(score {})", c.score).bright_white()
        );

        for (label, value) in &c.hits {
            println!(
                "{} {}: {}",
                ";".bright_black(),
                label.bright_black(),
                value.bright_white()
            );
        }

        println!("{}", ";".bright_black());
    }

    println!("{}", ";".bright_black());
}

/*
pub fn print_compiler_info(bytes: &[u8]) {
    print_msvc_info(bytes);
    print_gcc_info(bytes);
    print_gpp_info(bytes);
    print_clang_info(bytes);
    print_clangpp_info(bytes);
    print_rustc_info(bytes);
    print_golang_info(bytes);
}

fn print_gcc_info(bytes: &[u8]) {
    let gcc_version = find_string_in_bytes(bytes, b"GCC:");
    let gcc_compiler = find_string_in_bytes(bytes, b"GNU C");

    if let Some(v) = gcc_version {
        println!(
            "{} {}",
            "; Detected compiler version:".bright_black(),
            format!("gcc {v}").bright_white()
        );
    }

    if let Some(c) = gcc_compiler {
        println!(
            "{} {}",
            "; Detected compiler:".bright_black(),
            format!("gcc {c}").bright_white()
        );
    }

    println!("{}", ";".bright_black());
}

fn print_gpp_info(bytes: &[u8]) {
    let gpp_version = find_string_in_bytes(bytes, b"G++");
    let libstdcpp = find_string_in_bytes(bytes, b"libstdc++");

    if let Some(v) = gpp_version {
        println!(
            "{} {}",
            "; Detected compiler version:".bright_black(),
            format!("g++ {v}").bright_white()
        );
    }

    if let Some(v) = libstdcpp {
        println!(
            "{} {}",
            "; Detected stdlib:".bright_black(),
            format!("g++ {v}").bright_white()
        );
    }

    println!("{}", ";".bright_black());
}

fn print_clang_info(bytes: &[u8]) {
    let clang_version = find_string_in_bytes(bytes, b"clang version");
    let llvm_version = find_string_in_bytes(bytes, b"LLVM");

    if let Some(v) = clang_version {
        println!(
            "{} {}",
            "; Detected compiler version:".bright_black(),
            format!("clang {v}").bright_white()
        );
    }

    if let Some(v) = llvm_version {
        println!(
            "{} {}",
            "; Detected backend:".bright_black(),
            format!("llvm {v}").bright_white()
        );
    }

    println!("{}", ";".bright_black());
}

fn print_clangpp_info(bytes: &[u8]) {
    let clang_version = find_string_in_bytes(bytes, b"clang version");
    let libcxx = find_string_in_bytes(bytes, b"libc++");

    if let Some(v) = clang_version {
        println!(
            "{} {}",
            "; Detected compiler version:".bright_black(),
            format!("clang++ {v}").bright_white()
        );
    }

    if let Some(v) = libcxx {
        println!(
            "{} {}",
            "; Detected standard library:".bright_black(),
            format!("clang++ {v}").bright_white()
        );
    }

    println!("{}", ";".bright_black());
}

fn print_msvc_info(bytes: &[u8]) {
    let msvc = find_string_in_bytes(bytes, b"MSVC");
    let cl = find_string_in_bytes(bytes, b"Microsoft (R) C/C++");

    if let Some(v) = msvc {
        println!(
            "{} {}",
            "; Detected compiler:".bright_black(),
            format!("msvc {v}").bright_white()
        );
    }

    if let Some(v) = cl {
        println!(
            "{} {}",
            "; Detected toolchain:".bright_black(),
            format!("msvc cl {v}").bright_white()
        );
    }

    println!("{}", ";".bright_black());
}

fn print_rustc_info(bytes: &[u8]) {
    // Cerca stringhe di versione Rust nel binario — presenti nei binari non stripped
    let rust_version = find_string_in_bytes(bytes, b"rustc ");
    let rust_edition = find_string_in_bytes(bytes, b"rust edition");

    if let Some(version) = rust_version {
        println!(
            "{} {}",
            "; Detected language version:".bright_black(),
            format!("rust {version}").bright_white()
        );
    }

    if let Some(edition) = rust_edition {
        println!(
            "{} {}",
            "; Detected language edition:".bright_black(),
            format!("rust {edition}").bright_white()
        );
    }

    // Cerca nomi di crate nel formato "crate-name-X.Y.Z"
    let crates = find_crate_names(bytes);
    if !crates.is_empty() {
        println!("{}", "; Used crates      :".bright_black());
        for c in &crates {
            println!("{}   {}", ";".bright_black(), c.bright_white());
        }
    }
    println!("{}", ";".bright_black());
}

fn print_golang_info(bytes: &[u8]) {
    let go_version = find_string_in_bytes(bytes, b"go1.");
    let build_id = find_string_in_bytes(bytes, b"Go build ID");

    if let Some(v) = go_version {
        println!(
            "{} {}",
            "; Detected language version:".bright_black(),
            format!("go {v}").bright_white()
        );
    }

    if let Some(v) = build_id {
        println!(
            "{} {}",
            "; Detected build metadata:".bright_black(),
            format!("go {v}").bright_white()
        );
    }

    println!("{}", ";".bright_black());
}

fn find_crate_names(bytes: &[u8]) -> Vec<String> {
    // I nomi dei crate nel binario Rust hanno il formato "nome-X.Y.Z"
    // Cerca pattern ASCII che corrispondono
    let mut crates = Vec::new();
    let text: Vec<u8> = bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b
            } else {
                b'\n'
            }
        })
        .collect();
    let text = String::from_utf8_lossy(&text);

    for word in text.split_whitespace() {
        // Pattern: lowercase-with-hyphens-1.2.3
        if is_crate_name(word) {
            crates.push(word.to_string());
        }
    }
    crates.sort();
    crates.dedup();
    crates
}

fn is_crate_name(s: &str) -> bool {
    // "nome_crate-1.23.4" — almeno un trattino, finisce con cifre separate da punti
    let parts: Vec<&str> = s.rsplitn(2, '-').collect();
    if parts.len() != 2 {
        return false;
    }
    let version = parts[0];
    let name = parts[1];
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '-' || c == '_')
        && version.split('.').count() >= 2
        && version.chars().all(|c| c.is_ascii_digit() || c == '.')
}
*/
