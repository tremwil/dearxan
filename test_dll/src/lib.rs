use std::fs::File;

use dearxan::disabler::neuter_arxan;
use windows::Win32::{
    Foundation::HMODULE,
    System::{
        Console::{ATTACH_PARENT_PROCESS, AllocConsole, AttachConsole},
        LibraryLoader::DisableThreadLibraryCalls,
        SystemServices::DLL_PROCESS_ATTACH,
    },
};

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    h_inst_dll: HMODULE,
    fdw_reason: u32,
    _lpv_reserved: *const (),
) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(h_inst_dll.into()).ok();
            AttachConsole(ATTACH_PARENT_PROCESS).or_else(|_| AllocConsole()).unwrap();
        };
        simplelog::CombinedLogger::init(vec![
            simplelog::TermLogger::new(
                simplelog::LevelFilter::Debug,
                simplelog::Config::default(),
                simplelog::TerminalMode::Stdout,
                simplelog::ColorChoice::Auto,
            ),
            simplelog::WriteLogger::new(
                simplelog::LevelFilter::Trace,
                simplelog::Config::default(),
                File::options()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open("arxan-disabler-dll.log")
                    .unwrap(),
            ),
        ])
        .unwrap();

        unsafe {
            neuter_arxan(|entry, has_arxan| {
                log::info!(
                    "arxan detected: {has_arxan} true entry point: {:x}",
                    entry.addr()
                );
            })
        };
    }
    1
}
