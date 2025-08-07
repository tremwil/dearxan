use std::{
    env::current_dir,
    error::Error,
    ffi::CString,
    os::windows::io::{FromRawHandle, OwnedHandle},
    time::Duration,
};

use clap::Parser;
use dll_syringe::{
    Syringe,
    process::{OwnedProcess, Process},
};
use windows::{
    Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessA, INFINITE, PROCESS_INFORMATION, ResumeThread,
        STARTUPINFOA, WaitForSingleObject,
    },
    core::PCSTR,
};

struct Game {
    alias: &'static str,
    appid: u32,
    exe_path: &'static str,
}

impl Game {
    const fn new(alias: &'static str, appid: u32, exe_path: &'static str) -> Self {
        Self {
            alias,
            appid,
            exe_path,
        }
    }
}

const GAMES: &[Game] = &[
    Game::new("ds2s", 335300, "Game/DarkSoulsII.exe"),
    Game::new("ds3", 374320, "Game/DarkSoulsIII.exe"),
    Game::new("dsr", 570940, "DarkSoulsRemastered.exe"),
    Game::new("sdt", 814380, "sekiro.exe"),
    Game::new("er", 1245620, "Game/eldenring.exe"),
    Game::new("ac6", 1888160, "Game/armoredcore6.exe"),
    Game::new("nr", 2622380, "Game/nightreign.exe"),
];

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    #[arg(
        value_name = "GAME",
        help = "Game alias or executable path to start and inject the arxan disabler into.",
        long_help = "Game alias or executable path to start and inject the arxan disabler into. The valid aliases are:
\t- ds2s (Dark Souls II SOTFS) 
\t- ds3 (Dark Souls III) 
\t- dsr (Dark Souls Remastered) 
\t- sdt (Sekiro) 
\t- er (Elden Ring)
\t- nr (Elden Ring: Nightreign)
"
    )]
    game: String,

    #[arg(
        short,
        long,
        value_name = "SECONDS",
        help = "Time to wait before resuming the game process."
    )]
    delay: Option<f64>,

    #[arg(
        short,
        long,
        action = clap::ArgAction::SetTrue,
        help = "Wait for user input before resuming the game process."
    )]
    wait_for_input: bool,

    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        help = "Skip injecting the arxan disabler, just launch the game."
    )]
    no_inject: bool,

    #[arg(
        long,
        value_name = "APPID",
        help = "Optionally override the appid given to the game on launch."
    )]
    env_app_id: Option<u32>,

    #[arg(short, long, help = "Instrument Arxan stub invocations")]
    instrument_stubs: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Debug,
        simplelog::Config::default(),
        simplelog::TerminalMode::Stdout,
        simplelog::ColorChoice::Auto,
    )?;

    let args = CliArgs::parse();
    let lowercase_game_alias = args.game.to_lowercase();
    let (game_path, appid) = match GAMES.iter().find(|game| game.alias == lowercase_game_alias) {
        Some(game) => {
            let (game_app, game_lib) =
                steamlocate::SteamDir::locate()?.find_app(game.appid)?.ok_or(format!(
                    "Game '{lowercase_game_alias}' (app ID {}) not found in local Steam libraries",
                    game.appid
                ))?;

            (
                game_lib.resolve_app_dir(&game_app).join(game.exe_path),
                args.env_app_id.unwrap_or(game.appid),
            )
        }
        None => {
            log::info!("unknown game alias, assuming path to executable");
            let appid = args
                .env_app_id
                .ok_or("--env_app_id must be specified when using an explicit executable path")?;
            (args.game.into(), appid)
        }
    };

    let game_dir = game_path.parent().unwrap();
    let game_path_cstr = CString::new(game_path.as_os_str().to_str().unwrap())?;
    let game_dir_cstr = CString::new(game_dir.as_os_str().to_str().unwrap())?;

    let dll_path = if !args.no_inject {
        let mut build_args = vec!["build", "--release", "-p", "dearxan-test-dll"];
        if args.instrument_stubs {
            build_args.extend_from_slice(&["-F", "instrument_stubs"]);
        }
        log::info!("Building test DLL");
        std::process::Command::new("cargo").args(build_args).status()?;

        let dll_path = current_dir()?.join("target/release/dearxan_test_dll.dll");
        log::info!("DLL path: {}", dll_path.display());
        Some(dll_path)
    }
    else {
        None
    };

    log::info!("Game path: {}", game_path.display());

    log::info!("Launching with app ID: {}", appid);
    unsafe { std::env::set_var("SteamAppId", appid.to_string()) };

    let startup = STARTUPINFOA {
        cb: size_of::<STARTUPINFOA>().try_into()?,
        ..Default::default()
    };
    let mut proc_info = PROCESS_INFORMATION::default();

    let proc = unsafe {
        CreateProcessA(
            PCSTR(game_path_cstr.as_ptr() as *const _),
            None,
            None,
            None,
            true,
            CREATE_SUSPENDED,
            None,
            PCSTR(game_dir_cstr.as_ptr() as *const _),
            &startup,
            &mut proc_info,
        )?;

        let handle = OwnedHandle::from_raw_handle(proc_info.hProcess.0);
        OwnedProcess::from_handle_unchecked(handle).kill_on_drop()
    };

    log::info!(
        "Created suspended game process. PID = {}",
        proc_info.dwProcessId
    );

    if let Some(dll_path) = dll_path {
        log::info!("Injecting DLL");
        let syringe = Syringe::for_process(proc.try_clone()?);
        let _ = syringe.inject(dll_path)?;
        log::info!("DLL injected");
    }

    if let Some(delay) = args.delay {
        log::info!("Waiting {delay:.2} seconds before resuming process");
        std::thread::sleep(Duration::from_secs_f64(delay));
    }

    if args.wait_for_input {
        log::info!("Press enter to resume process. Output will appear below.");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
    else {
        log::info!("Resuming process. Output will appear below");
    }

    unsafe {
        ResumeThread(proc_info.hThread);
        WaitForSingleObject(proc_info.hProcess, INFINITE);
    }

    Ok(())
}
