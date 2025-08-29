# dearxan

`dearxan` is a library for performing static and runtime analysis/patching of the checks Arxan (now GuardIT) inserts in a binary.

It is currently able to fully[^1] neuter Arxan in all the FromSoftware games using it. In particular, once patches are applied absolutely zero Arxan code (e.g. anti-debug checks and integrity checks) will run and all encrypted functions will be forever decrypted.

[^1]: This is not quite true at the moment, since we still have to let the Arxan entry point stubs run. This is not really a problem as the entry point stub does not do any anti-debug checks. In some games (e.g. Dark Souls Remastered) these stubs perform integrity checks and crash the game if modifications are detected, which can be mitigated by performing your hooks in the callback function provided to `neuter_arxan`. Once the entry point stubs are fully reverse engineered, this will no longer be necessary.

Note that this crate is only tested against the variants of Arxan present in the latest versions FromSoftware games, which is all of the following:
- Dark Souls Remastered
- Dark Souls II SOTFS
- Dark Souls III
- Elden Ring
- Armored Core VI
- Elden Ring: Nightreign

It may not work with the Arxan configurations used by other game developers. That said, contributions are welcome.

# Usage

## From Rust, using the `disabler` feature

Add the following to your `Cargo.toml`:
```toml
dearxan = "0.3.1"
```

Then, simply call the `dearxan::disabler::neuter_arxan` function once before the entry point of the game is executed: 
```rust,
unsafe fn runs_before_entry_point() {
    use dearxan::disabler::neuter_arxan;

    neuter_arxan(|result| {
        match result {
            Ok(_status) => println!("Arxan disabled!"),
            Err(e) => println!("{e}\nFailed to disable Arxan!"),
        }
        // This is a good place to do your hooks.
        // Once this callback returns, the game's true entry point
        // will be invoked.
    });
}
```

## From C++

Download the static library from the [Releases](https://github.com/tremwil/dearxan/releases) page and link to it along with the included Windows import libraries. Include `include/dearxan.h` and call `dearxan::neuter_arxan` before the game's entry point runs:

```C++
#include <iostream>

#include "include/dearxan.h"

void runs_before_entry_point() {
    dearxan::neuter_arxan([](const dearxan::DearxanResult& result) {
        if (result.status() == dearxan::DearxanStatus::DearxanSuccess) {
            std::cout << "Arxan disabled!\n";
        } else {
            std::cout << result.error_msg() << '\n';
            std::cout << "Failed to disable Arxan!\n";
        }
    });
}
```

Note that the minimal supported C++ standard is C++14, although C++17 and above are recommended.

## From C

Download the static library from the [Releases](https://github.com/tremwil/dearxan/releases) page and link to it along with the included Windows import libraries. Include `include/dearxan.h` and call `dearxan_neuter_arxan` before the game's entry point runs:

```C
#include <stdio.h>

#include "include/dearxan.h"

void my_callback(const DearxanResult* result, void* opaque) {
    if (result->status == DearxanSuccess) {
        printf("Arxan disabled!\n");
    } else {
        printf(
            "%.*s\nFailed to disable Arxan!\n",
            (int)result->error_msg_size,
            result->error_msg
        );
    }
}

void runs_before_entry_point() {
    dearxan_neuter_arxan(my_callback, NULL);
}
```

## From another language

Download the static library from the [Releases](https://github.com/tremwil/dearxan/releases) page and  link to it along with the included Windows import libraries. Generate C bindings according to `include/dearxan.h` and call `dearxan_neuter_arxan` before the game's entry point runs.

## Writing your own patcher

If you want to patch an executable on disk, for example, you will need to write your own disabler. This will involve analyzing the Arxan stubs in the binary with `dearxan::analysis::analyze_all_stubs` or equivalent APIs, then passing the resulting `StubInfo` values to `dearxan::patch::ArxanPatch::build_from_stubs`. From there you will have to iterate over the patches and apply them to the executable manually.

Note that currently, for this to work on a live executable image it is important to make sure that the Arxan entry point stub has been invoked. For FromSoftware games, beware that binaries may be wrapped in SteamStub as well. 

# About Arxan

Arxan is an anti debug and tampering product often applied to games. Some features of Arxan include:
- Instruction mutations and control flow obfuscation to confuse decompilers and make reverse engineering harder
- Obfuscation by encrypting sensitive functions at rest and decrypting them only when they are being executed
- A varied suite of anti-debug checks
- Integrity checks on functions marked as sensitive by the game developer, with the ability to a combination of the following when tampering is detected:
  - Silently writing flags to a buffer that the game developer can read to integrate with their anti-cheat solution
  - Crashing the game by corrupting the stack or control flow in a way that is difficult to debug
  - Repairing the function's code

Every bit of new logic (e.g. not just instruction mutations) that Arxan adds to the game is contained within an *Arxan stub* that is inserted into an arbitrary game function. These stubs perform a context save by pushing the registers they will be using on the stack before executing some Arxan logic, restoring the context and jumping back to the function's original code.

This crate disables Arxan by searching for these stubs and visting their control flow graphs. Using partial instruction emulation and forking the program state when branches are hit, it is possible to work through Arxan's control flow obfuscation. From there, the structure of the stubs is analyzed to extract the patches required to neuter it. This is usually a jump hook to a special trampoline that fixes up the stub's stack, and sometimes includes extracting the code regions decrypted by the stub to write their contents directly.

# Feature flags

The crate comes with the following feature flags:
- `disabler` (default): Provides an implementation of a patcher capable of fully disabling Arxan by calling the `neuter_arxan` function.
- `rayon` (default): Parallelizes Arxan stub analysis using the `rayon` crate.
- `ffi`: Exports a C function `dearxan_neuter_arxan` to use the Arxan disabler from another language.
- `instrument_stubs`: Adds upon `disabler` by instrumenting each Arxan stub to log a message the first time it is called. **CAREFUL**: This feature currently crashes for games other than Dark Souls Remastered due to register clobbering! 
- `internal_api`: Make most of the internal binary analysis APIs public through `dearxan::analysis::internal`. These APIs are *not* stabilized yet and may break between minor crate versions.

# Credits

Many thanks to [dasaav](https://github.com/Dasaav-dsv/) for implementing global synchronization for `neuter_arxan` ad well as helping me reverse engineer how Arxan stores the regions of memory to decrypt and for finding the encryption algorithm they used (32-round TEA).