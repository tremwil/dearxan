#ifndef _DEARXAN_H
#define _DEARXAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Callback invoked once arxan has been disabled (or if it wasn't detected).
typedef void (*DearxanUserCallback)(uint64_t original_entry_point, bool arxan_detected, void* context);

/// Single function to neuter all of Arxan's checks.
///
/// The callback will be invoked with the true entry point of the program once patching
/// is complete, and a bool indicating whether Arxan was detected. It can be used to initialize
/// hooks/etc.
///
/// Handles SteamStub 3.1 possibly being applied on top of Arxan.
///
/// # Panics
/// If called more than once.
///
/// # Safety
/// This function must be called before the game's entry point runs. It is generally safe to call
/// from within DllMain.
extern void dearxan_neuter_arxan(DearxanUserCallback callback, void* context);

#ifdef __cplusplus
};
#endif
#endif