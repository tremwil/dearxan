import os, shutil, json, package_version

print("clearing dist directory")

shutil.rmtree("target\\dist", ignore_errors=True)
os.makedirs("target\\dist\\lib", exist_ok=True)
shutil.copytree("include", "target\\dist\\include")

print("building static library")

os.environ["RUSTFLAGS"] = "--print=native-static-libs " + (os.environ.get("RUSTFLAGS") or "")

os.system("cargo build --release -F ffi")
shutil.copy("target\\release\\dearxan.lib", "target\\dist\\lib\\dearxan.lib")

build_output = os.popen("cargo build --release -F ffi --message-format json")
json_outputs = [json.loads(line) for line in build_output.readlines()]
messages = [j["message"]["message"] for j in json_outputs if j["reason"] == "compiler-message"]
libs = [lib for m in messages for lib in m.split(" ")[1:] if m.startswith("native-static-libs:")]

print("linked static libraries:", libs)

WIN_SDKS_PATH = "C:\\Program Files (x86)\\Windows Kits\\10\\Lib"
latest_sdk_ver = max(d for d in os.listdir(WIN_SDKS_PATH) if d.startswith("10."))
print("pulling static libraries from Windows SDK:", latest_sdk_ver)

libs_folder = os.path.join(WIN_SDKS_PATH, latest_sdk_ver, "um\\x64")
lib_paths = {p for p in map(lambda l: os.path.join(libs_folder, l), libs) if os.path.exists(p)}

for lib in lib_paths:
    print(lib)
    shutil.copy(lib, "target\\dist\\lib")

with open("target\\dist\\lib\\readme.txt", "w") as f:
    f.write("'dearxan.lib' depends on the following Windows SDK import libraries:\n")
    f.writelines(f"- {os.path.basename(p)}\n" for p in lib_paths)
    f.write(
        "\nWhile they have been copied to this folder, if building with MSVC it is recommended " \
        "to link to the ones that ship with your Windows SDK."
    )

print("Zipping static libraries")
shutil.make_archive(f"target\\dearxan-{package_version.get_version()}", format="zip", root_dir="target\\dist")