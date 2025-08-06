import package_version, re

version = package_version.get_version()

with open("CHANGELOG.md", "r") as f:
    changelog = f.read()

regex = re.compile(r"\[v" + version.replace(".", "\\.") + r"\][^\n]*\n+(.*?)\n(\#\#|\Z)", re.S)
changes = next(regex.finditer(changelog)).group(1)

print(changes)