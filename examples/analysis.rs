use std::path::PathBuf;

use clap::Parser;
use dearxan::analysis::{StubAnalyzer, analyze_all_stubs_with, encryption};
use dearxan_test_utils::{FsExe, fsbins, init_log};

#[derive(Parser)]
#[command(version, about = "Analyze a single Arxan stub", long_about = None)]
struct CliArgs {
    #[arg(value_name = "GAME", help = "Game executable to analyze")]
    game: String,

    #[arg(
        short,
        long,
        help = "Version of the game executable to analyze (default latest)"
    )]
    ver: Option<String>,

    #[arg(
        short, long,
        value_name = "PTR",
        help = "Address of stub's TEST RSP, 15 instruction, or none for all stubs",
        value_parser=clap_num::maybe_hex::<u64>
    )]
    address: Option<u64>,

    #[arg(
        short,
        long,
        help = "Enable trace logs, including full program CFG visit"
    )]
    trace: bool,
}

fn main() {
    init_log(log::LevelFilter::Trace);

    let args = CliArgs::parse();
    let game = if matches!(std::fs::exists(&args.game), Ok(true)) {
        let path = PathBuf::from(&args.game);
        log::info!("assuming game is the executable at '{}'", args.game);
        FsExe {
            game: path.file_stem().unwrap().to_string_lossy().to_string(),
            ver: "0".to_string(),
            path,
        }
    }
    else {
        fsbins()
            .iter()
            .find(|g| g.name.eq_ignore_ascii_case(&args.game))
            .and_then(|g| {
                args.ver
                    .map(|tgt| g.versions.iter().find(|exe| exe.ver == tgt))
                    .unwrap_or(g.versions.last())
            })
            .expect("game or version not found")
            .clone()
    };

    if !args.trace {
        log::set_max_level(log::LevelFilter::Debug);
    }

    let mapped_game = game.load_64().expect("failed to load the game's executable image");
    let pe = mapped_game.pe_view();

    let analyzer = StubAnalyzer::new().trace_execution(args.trace);

    let stub_infos = match args.address {
        Some(addr) => {
            log::info!("analyzing stub {:x} of {} v{}", addr, game.game, game.ver);
            vec![analyzer.analyze(&pe, addr)]
        }
        None => {
            log::info!("analyzing all stubs of {} v{}", game.game, game.ver);
            analyze_all_stubs_with(pe, analyzer)
        }
    };

    log::info!("found {} Arxan stubs", stub_infos.len());

    for stub_info_result in &stub_infos {
        let stub_info = match stub_info_result {
            Ok(si) => si,
            Err(e) => {
                log::warn!("{e}");
                continue;
            }
        };

        println!("\nSTUB {:x}:", stub_info.test_rsp_va);
        println!("context_pop_va: {:x}", stub_info.context_pop_va);
        println!("return_gadget : {:x?}", stub_info.return_gadget);

        if let Some(region_list) = &stub_info.encrypted_regions {
            println!(
                "writes {} contiguous {:?} encrypted regions",
                region_list.len(),
                region_list.kind
            );
        }
    }

    let final_patches = encryption::apply_relocs_and_resolve_conflicts(
        stub_infos
            .iter()
            .filter_map(|si| si.as_ref().ok())
            .filter_map(|si| si.encrypted_regions.as_ref()),
        pe,
        None,
    )
    .unwrap();

    for rlist in final_patches {
        println!(
            "\n{} contiguous {:?} encrypted regions",
            rlist.len(),
            rlist.kind
        );

        for r in &rlist.regions {
            println!(
                "rva = {:x} {}",
                r.rva,
                pretty_hex::pretty_hex(&r.decrypted_slice(&rlist).unwrap())
            );
        }
    }
}
