#!/usr/bin/env python3
"""Copy the host's Python 3.10 OpenAI SDK into an offline Docker context."""

from importlib import metadata
from pathlib import Path
import shutil
import sys


if sys.version_info[:2] != (3, 10):
    raise SystemExit("需要物理机 Python 3.10，与镜像内 Python 版本一致")

destination = Path(sys.argv[1]).resolve()
destination.mkdir(parents=True, exist_ok=True)

packages = (
    "openai", "anyio", "httpx", "jiter", "pydantic", "sniffio", "tqdm",
    "typing_extensions", "httpcore", "h11", "annotated_types", "pydantic_core",
    "typing_inspection", "exceptiongroup",
)
for name in packages:
    package = metadata.distribution(name)
    root = Path(package.locate_file("")).resolve()
    for entry in package.files or ():
        source = Path(package.locate_file(entry)).resolve()
        try:
            relative = source.relative_to(root)
        except ValueError:
            continue
        if source.is_file():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

system_packages = Path("/usr/lib/python3/dist-packages")
for name in ("distro", "certifi", "idna"):
    shutil.copytree(system_packages / name, destination / name, dirs_exist_ok=True)
