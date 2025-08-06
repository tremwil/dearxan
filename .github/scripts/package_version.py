import os, json

def get_version() -> str:
    cargo_meta = json.loads(os.popen("cargo metadata --format-version 1 -q").read())
    return next(p["version"] for p in cargo_meta["packages"] if p["name"] == "dearxan")

if __name__ == '__main__':
    print(get_version())