use clap::Parser;
use dearxan::analysis::{StubAnalyzer, analyze_all_stubs_with};
use dearxan_test_utils::{fsbins, init_log};

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
    let game = fsbins()
        .iter()
        .find(|g| g.name.eq_ignore_ascii_case(&args.game))
        .and_then(|g| {
            args.ver
                .map(|tgt| g.versions.iter().find(|exe| exe.ver == tgt))
                .unwrap_or(g.versions.last())
        })
        .expect("game or version not found");

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

    for stub_info_result in stub_infos {
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
            println!("writes {} contiguous encrypted regions:", region_list.len());

            for region in &region_list.regions {
                println!("- rva = {:x} size = {}", region.rva, region.size);
                match region.decrypted_slice(region_list) {
                    Some(r) => println!("{}", pretty_hex::pretty_hex(&r)),
                    None => log::warn!("this slice is out of bounds of the plaintext block!"),
                }
            }
        }
    }
}
