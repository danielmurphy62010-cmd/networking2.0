"""Build the Networking v2.0 Python extension."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pybind11
from setuptools import Extension, setup

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "build_config.json").read_text(encoding="utf-8"))
IS_WINDOWS = os.name == "nt"
COMPILER = "msvc" if IS_WINDOWS else "unix"
CXX_STANDARD = int(CONFIG.get("cxx_standard", 17))

if CXX_STANDARD < 17:
    raise ValueError("Networking v2.0 requires C++17 or newer")

extra_compile_args = list(CONFIG.get("compiler_args", {}).get(COMPILER, []))
if IS_WINDOWS:
    extra_compile_args.append(f"/std:c++{CXX_STANDARD}")
else:
    extra_compile_args.append(f"-std=c++{CXX_STANDARD}")

extension = Extension(
    name=CONFIG["module_name"],
    sources=[str(ROOT / source) for source in CONFIG["sources"]],
    include_dirs=[pybind11.get_include()],
    libraries=CONFIG["windows_libraries"] if IS_WINDOWS else CONFIG["unix_libraries"],
    language="c++",
    extra_compile_args=extra_compile_args,
)

setup(
    name="networking-v2",
    version="0.2.0",
    description="Networking v2.0 C++ extension",
    ext_modules=[extension],
    zip_safe=False,
    python_requires=">=3.10",
)
