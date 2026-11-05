#!/usr/bin/env python3
"""Configuration-driven multi-language build orchestrator.

The runner's base Python only needs the standard library.  Conda environments,
Python packaging tools, and Rust/Go toolchains are provisioned here.

Supported language/target combinations:
  * cpp + python_extension  (setuptools + pybind11)
  * c/cpp + executable | shared_library | static_library
  * rust + executable      (Cargo)
  * rust + python_extension (Cargo + PyO3)
  * go + executable         (go build)
  * python + executable     (PyInstaller or Nuitka)

Example:
  python build/setup.py build --config build/build_config.json \
      --output "$RUNNER_TEMP/native-builds" --workers 4
"""
from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import tomllib
import traceback
from collections import OrderedDict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = SCRIPT_DIR / "build_config.json"
REPO_ROOT = SCRIPT_DIR.parent
FINGERPRINT_FILE = ".build-engine-fingerprint.json"
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*$")


class BuildError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BuildError(f"{name} must be a JSON object")
    return value


def require_string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise BuildError(f"{name} must be {'a string' if allow_empty else 'a non-empty string'}")
    return value


def string_list(value: Any, name: str, *, default: list[str] | None = None) -> list[str]:
    if value is None:
        return list(default or [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise BuildError(f"{name} must be an array of strings")
    return list(value)


def safe_component(value: str, name: str) -> str:
    if not SAFE_NAME.fullmatch(value) or value in {".", "..", "_temp"}:
        raise BuildError(f"{name} must be a safe filename component: {value!r}")
    return value


def load_config(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BuildError(f"Configuration file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BuildError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(raw, dict) or not raw:
        raise BuildError("build_config.json must be a non-empty JSON object")

    settings = raw.get("settings", {})
    require_dict(settings, "settings")
    modules = {key: value for key, value in raw.items() if key != "settings"}
    if not modules:
        raise BuildError("build_config.json does not contain any modules")

    folded: set[str] = set()
    for module_key, module_config in modules.items():
        safe_component(module_key, "Top-level module names")
        if module_key.casefold() in folded:
            raise BuildError(f"Module names must be unique ignoring case: {module_key!r}")
        folded.add(module_key.casefold())
        require_dict(module_config, f"{module_key}")
    return settings, modules


def current_platform() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    raise BuildError(f"Unsupported runner platform: {sys.platform!r}; only Windows and Linux are supported")


def resolve_path(value: str, name: str, *, base: Path = REPO_ROOT) -> Path:
    path = Path(value).expanduser()
    resolved = path if path.is_absolute() else (base / path)
    return resolved.resolve()


def existing_sources(module_key: str, values: Any) -> list[str]:
    sources = string_list(values, f"{module_key}.sources")
    if not sources:
        raise BuildError(f"{module_key}.sources must contain at least one source file")
    resolved: list[str] = []
    for source in sources:
        path = resolve_path(source, f"{module_key}.sources")
        if not path.is_file():
            raise BuildError(f"Source file for {module_key!r} does not exist: {path}")
        resolved.append(str(path))
    return resolved


def platform_enabled(module_key: str, config: dict[str, Any], platform_name: str) -> bool:
    platforms = config.get("platforms", ["linux", "windows"])
    if (
        not isinstance(platforms, list)
        or not platforms
        or any(not isinstance(item, str) or item not in {"linux", "windows"} for item in platforms)
    ):
        raise BuildError(f"{module_key}.platforms must contain 'linux' and/or 'windows'")
    return platform_name in platforms


def normalized_language(config: dict[str, Any]) -> str:
    # The default preserves the original setup.py's C++/pybind11 behavior.
    language = config.get("language", "cpp")
    if not isinstance(language, str):
        raise BuildError("language must be a string")
    language = language.strip().lower()
    aliases = {"c++": "cpp", "cxx": "cpp", "golang": "go"}
    language = aliases.get(language, language)
    if language not in {"c", "cpp", "rust", "go", "python"}:
        raise BuildError(f"Unsupported language: {language!r}")
    return language


def normalized_target(language: str, config: dict[str, Any]) -> str:
    # Backward compatibility: an old module with sources/module_name was a
    # pybind11 extension, even if it did not have language/target fields.
    default = "python_extension" if language == "cpp" and "language" not in config else "executable"
    target = config.get("target", default)
    if not isinstance(target, str):
        raise BuildError("target must be a string")
    target = target.strip().lower().replace("-", "_")
    allowed = {
        "c": {"executable", "shared_library", "static_library"},
        "cpp": {"executable", "shared_library", "static_library", "python_extension"},
        "rust": {"executable", "python_extension"},
        "go": {"executable"},
        "python": {"executable"},
    }
    if target not in allowed[language]:
        raise BuildError(f"Unsupported target {target!r} for language {language!r}; expected one of {sorted(allowed[language])}")
    if target == "python_extension" and language not in {"cpp", "rust"}:
        raise BuildError("python_extension is supported for cpp/pybind11 and rust/PyO3 modules")
    return target


def python_settings(module_key: str, config: dict[str, Any]) -> dict[str, Any]:
    value = config.get("python", {})
    result = require_dict(value, f"{module_key}.python")
    versions = result.get("versions", ["3.12"])
    if isinstance(versions, (str, int, float)):
        versions = [versions]
    if not isinstance(versions, list) or not versions or any(not isinstance(v, (str, int, float)) for v in versions):
        raise BuildError(f"{module_key}.python.versions must be a non-empty string/number array")

    version_specs: list[dict[str, str | None]] = []
    seen_version_specs: set[tuple[str, bool]] = set()
    for raw_version in versions:
        version_text = str(raw_version).strip()
        explicit_free_threaded = version_text.lower().endswith("t")
        version = version_text[:-1] if explicit_free_threaded else version_text
        if not version:
            raise BuildError(f"{module_key}.python.versions contains an empty version")
        key = (version, explicit_free_threaded)
        if key in seen_version_specs:
            raise BuildError(f"{module_key}.python.versions contains a duplicate entry: {version_text!r}")
        seen_version_specs.add(key)
        version_specs.append({
            "version": version,
            "explicit_abi": "free-threaded" if explicit_free_threaded else None,
        })

    result = dict(result)
    options = require_dict(result.get("options", {}), f"{module_key}.python.options")
    # Accept the nested options form from the documented example as well as
    # direct keys, with direct keys taking precedence.
    for option_key, option_value in options.items():
        result.setdefault(option_key, option_value)

    raw_abis = result.get("abis", result.get("abi", "gil"))
    if result.get("free_threaded") is True:
        raw_abis = "free-threaded"
    if isinstance(raw_abis, str):
        raw_abis = [raw_abis]
    if not isinstance(raw_abis, list) or not raw_abis or any(not isinstance(item, str) for item in raw_abis):
        raise BuildError(f"{module_key}.python.abi/abis must be a string or a non-empty array of strings")

    aliases = {
        "gil": "gil",
        "standard": "gil",
        "gil-enabled": "gil",
        "free-threaded": "free-threaded",
        "free_threaded": "free-threaded",
        "nogil": "free-threaded",
        "t": "free-threaded",
        "both": "both",
    }
    abis: list[str] = []
    for raw_abi in raw_abis:
        normalized = aliases.get(raw_abi.strip().lower())
        if normalized is None:
            raise BuildError(f"{module_key}.python.abi contains an unsupported value: {raw_abi!r}")
        values = ["gil", "free-threaded"] if normalized == "both" else [normalized]
        for abi in values:
            if abi not in abis:
                abis.append(abi)

    result["versions"] = list(dict.fromkeys(spec["version"] for spec in version_specs))
    result["version_specs"] = version_specs
    result["abis"] = abis
    # Keep the legacy single-ABI field readable for configs/tools that inspect it.
    result["abi"] = abis[0] if len(abis) == 1 else list(abis)
    result["conda_dependencies"] = string_list(result.get("conda_dependencies"), f"{module_key}.python.conda_dependencies")
    result["pip_dependencies"] = string_list(result.get("pip_dependencies"), f"{module_key}.python.pip_dependencies")
    return result


def python_variants(module_key: str, py: dict[str, Any]) -> list[tuple[str, str]]:
    """Expand versions and ABIs into valid interpreter build variants."""
    variants: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for version_spec in py["version_specs"]:
        version = version_spec["version"]
        requested_abis = [version_spec["explicit_abi"]] if version_spec["explicit_abi"] else py["abis"]
        for abi in requested_abis:
            if abi == "free-threaded" and version != "stable":
                match = re.match(r"^(\d+)\.(\d+)", version)
                if match and tuple(map(int, match.groups())) < (3, 13):
                    if version_spec["explicit_abi"]:
                        raise BuildError(f"Free-threaded CPython requires Python 3.13 or newer; got {version}")
                    log(f"SKIP {module_key}: Python {version} has no free-threaded ABI")
                    continue
            pair = (version, abi)
            if pair not in seen:
                variants.append(pair)
                seen.add(pair)
    if not variants:
        raise BuildError(f"{module_key}.python does not contain any supported version/ABI combinations")
    return variants


def python_conda_specs(version: str, abi: str) -> list[str]:
    """Select an explicit conda-forge Python flavour and minor version."""
    package = "python-freethreading" if abi == "free-threaded" else "python-gil"
    return [package if version == "stable" else f"{package}={version}"]


def env_fingerprint(specs: list[str], pip_specs: list[str], channels: list[str], platform_name: str) -> str:
    payload = json.dumps(
        {"conda": specs, "pip": pip_specs, "channels": channels, "platform": platform_name},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def make_env_definition(
    specs: list[str], pip_specs: list[str], channels: list[str], platform_name: str
) -> dict[str, Any]:
    fingerprint = env_fingerprint(specs, pip_specs, channels, platform_name)
    return {
        "id": fingerprint[:16],
        "fingerprint": fingerprint,
        "specs": list(dict.fromkeys(specs)),
        "pip_specs": list(dict.fromkeys(pip_specs)),
        "channels": channels,
    }


def add_task(
    tasks: list[dict[str, Any]],
    *,
    module_key: str,
    config: dict[str, Any],
    language: str,
    target: str,
    label: str,
    platform_name: str,
    output_root: Path,
    temp_root: Path,
    env: dict[str, Any] | None = None,
    python_version: str | None = None,
    abi: str | None = None,
) -> None:
    safe_component(module_key, "module name")
    safe_component(label, "build target label")
    output_dir = output_root / module_key / label
    work_dir = temp_root / module_key / label
    task = {
        "module": module_key,
        "config": config,
        "language": language,
        "target": target,
        "label": label,
        "platform": platform_name,
        "output_dir": str(output_dir),
        "work_dir": str(work_dir),
        "env": env,
        "python_version": python_version,
        "abi": abi,
        "repo_root": str(REPO_ROOT),
    }
    if env:
        task["resource_key"] = "env:" + env["fingerprint"]
    else:
        # Native compiler tasks have no mutable shared environment/cache.
        task["resource_key"] = "task:" + module_key + ":" + label
    tasks.append(task)


def plan_tasks(
    modules: dict[str, dict[str, Any]],
    platform_name: str,
    output_root: Path,
    temp_root: Path,
    channels: list[str],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    tasks: list[dict[str, Any]] = []
    envs: dict[str, dict[str, Any]] = {}
    skipped: list[str] = []

    for module_key, config in modules.items():
        if not platform_enabled(module_key, config, platform_name):
            skipped.append(module_key)
            continue

        language = normalized_language(config)
        target = normalized_target(language, config)
        base_pip = string_list(config.get("build_dependencies"), f"{module_key}.build_dependencies")

        if language in {"c", "cpp"} and target != "python_extension":
            existing_sources(module_key, config.get("sources"))
            add_task(
                tasks, module_key=module_key, config=config, language=language,
                target=target, label="native", platform_name=platform_name,
                output_root=output_root, temp_root=temp_root,
            )
            continue

        if language == "cpp" and target == "python_extension":
            py = python_settings(module_key, config)
            sources = existing_sources(module_key, config.get("sources"))
            for version, abi in python_variants(module_key, py):
                specs = ["pip", "setuptools", "wheel", *python_conda_specs(version, abi)]
                specs.extend(py["conda_dependencies"])
                pip_specs = list(py["pip_dependencies"])
                if not any(item.lower().split("[", 1)[0].split("=", 1)[0].split(">", 1)[0] == "pybind11" for item in pip_specs):
                    pip_specs.append("pybind11>=3.1.0")
                pip_specs.extend(base_pip)
                env = make_env_definition(specs, pip_specs, channels, platform_name)
                envs[env["fingerprint"]] = env
                version_label = "stable" if version == "stable" else version.replace(".", "")
                suffix = "t" if abi == "free-threaded" else ""
                label = f"python-{version_label}{suffix}"
                task_config = dict(config)
                task_config["_resolved_sources"] = sources
                add_task(
                    tasks, module_key=module_key, config=task_config, language=language,
                    target=target, label=label, platform_name=platform_name,
                    output_root=output_root, temp_root=temp_root, env=env,
                    python_version=version, abi=abi,
                )
            continue

        if language == "rust":
            rust = require_dict(config.get("rust", {}), f"{module_key}.rust")
            manifest = resolve_path(require_string(rust.get("manifest", "Cargo.toml"), f"{module_key}.rust.manifest"), f"{module_key}.rust.manifest")
            if not manifest.is_file():
                raise BuildError(f"Rust manifest does not exist for {module_key!r}: {manifest}")
            rust_version = rust.get("version", "stable")
            rust_specs = ["rust" if rust_version == "stable" else f"rust={rust_version}"]
            rust_specs.extend(string_list(rust.get("conda_dependencies"), f"{module_key}.rust.conda_dependencies"))
            task_config = dict(config)
            task_config["_resolved_manifest"] = str(manifest)
            task_config["rust"] = rust

            if target == "python_extension":
                py = python_settings(module_key, config)
                for python_version, abi in python_variants(module_key, py):
                    specs = ["pip", *python_conda_specs(python_version, abi), *rust_specs]
                    specs.extend(py["conda_dependencies"])
                    pip_specs = list(py["pip_dependencies"])
                    pip_specs.extend(base_pip)
                    env = make_env_definition(specs, pip_specs, channels, platform_name)
                    envs[env["fingerprint"]] = env
                    version_label = "stable" if python_version == "stable" else python_version.replace(".", "")
                    suffix = "t" if abi == "free-threaded" else ""
                    label = f"python-{version_label}{suffix}"
                    add_task(
                        tasks, module_key=module_key, config=task_config, language=language,
                        target=target, label=label, platform_name=platform_name,
                        output_root=output_root, temp_root=temp_root, env=env,
                        python_version=python_version, abi=abi,
                    )
            else:
                env = make_env_definition(rust_specs, [], channels, platform_name)
                envs[env["fingerprint"]] = env
                add_task(
                    tasks, module_key=module_key, config=task_config, language=language,
                    target=target, label="native", platform_name=platform_name,
                    output_root=output_root, temp_root=temp_root, env=env,
                )
            continue

        if language == "go":
            go = require_dict(config.get("go", {}), f"{module_key}.go")
            version = go.get("version", "stable")
            specs = ["go" if version == "stable" else f"go={version}"]
            specs.extend(string_list(go.get("conda_dependencies"), f"{module_key}.go.conda_dependencies"))
            env = make_env_definition(specs, [], channels, platform_name)
            envs[env["fingerprint"]] = env
            task_config = dict(config)
            task_config["go"] = go
            add_task(
                tasks, module_key=module_key, config=task_config, language=language,
                target=target, label="native", platform_name=platform_name,
                output_root=output_root, temp_root=temp_root, env=env,
            )
            continue

        if language == "python":
            py = python_settings(module_key, config)
            packager = py.get("packager", "pyinstaller")
            if packager not in {"pyinstaller", "nuitka"}:
                raise BuildError(f"{module_key}.python.packager must be 'pyinstaller' or 'nuitka'")
            entry = resolve_path(require_string(py.get("entry"), f"{module_key}.python.entry"), f"{module_key}.python.entry")
            if not entry.is_file():
                raise BuildError(f"Python entry point does not exist for {module_key!r}: {entry}")
            packager_spec = py.get("packager_version")
            pip_specs = list(py["pip_dependencies"])
            pip_specs.extend(base_pip)
            pip_specs.append(packager if not packager_spec else f"{packager}=={packager_spec}")
            for version, abi in python_variants(module_key, py):
                specs = ["pip", *python_conda_specs(version, abi)]
                specs.extend(py["conda_dependencies"])
                env = make_env_definition(specs, pip_specs, channels, platform_name)
                envs[env["fingerprint"]] = env
                version_label = "stable" if version == "stable" else version.replace(".", "")
                suffix = "t" if abi == "free-threaded" else ""
                label = f"python-{version_label}{suffix}"
                task_config = dict(config)
                task_config["python"] = dict(py)
                task_config["python"]["_resolved_entry"] = str(entry)
                add_task(
                    tasks, module_key=module_key, config=task_config, language=language,
                    target=target, label=label, platform_name=platform_name,
                    output_root=output_root, temp_root=temp_root, env=env,
                    python_version=version, abi=abi,
                )
            continue

    return tasks, envs, skipped


def resolve_conda() -> str:
    candidates = [os.environ.get("CONDA_EXE"), shutil.which("conda")]
    for candidate in candidates:
        if candidate:
            path = Path(candidate)
            if path.exists() or shutil.which(candidate):
                return str(path) if path.exists() else candidate
    raise BuildError(
        "Conda was not found. Install Miniconda in the workflow (for example with "
        "conda-incubator/setup-miniconda) and make sure CONDA_EXE or PATH exposes conda."
    )


def run_checked(command: list[str], *, cwd: str | Path | None = None, env: dict[str, str] | None = None) -> None:
    log("$ " + subprocess.list2cmdline(command))
    subprocess.run(command, cwd=cwd, env=env, check=True)


def capture_checked(
    command: list[str],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> str:
    log("$ " + subprocess.list2cmdline(command))
    result = subprocess.run(command, cwd=cwd, env=env, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def prepare_environment(
    conda: str,
    definition: dict[str, Any],
    env_root: Path,
) -> Path:
    prefix = env_root / ("env-" + definition["id"])
    marker = prefix / FINGERPRINT_FILE
    expected = {
        "fingerprint": definition["fingerprint"],
        "conda": definition["specs"],
        "pip": definition["pip_specs"],
        "channels": definition["channels"],
    }

    if (prefix / "conda-meta").is_dir() and marker.is_file():
        try:
            existing = json.loads(marker.read_text(encoding="utf-8"))
            if existing == expected:
                log(f"Reusing Conda environment {prefix}")
                return prefix
        except (OSError, json.JSONDecodeError):
            pass

    if prefix.exists():
        log(f"Removing incomplete/outdated environment {prefix}")
        shutil.rmtree(prefix, ignore_errors=True)

    prefix.parent.mkdir(parents=True, exist_ok=True)
    command = [conda, "create", "--yes", "--prefix", str(prefix), "--override-channels", "--strict-channel-priority"]
    for channel in definition["channels"]:
        command.extend(["--channel", channel])
    command.extend(definition["specs"])
    log(f"Preparing environment {definition['id']} ({', '.join(definition['specs'])})")
    run_checked(command)

    if definition["pip_specs"]:
        pip_command = [
            conda, "run", "--prefix", str(prefix), "--no-capture-output",
            "python", "-m", "pip", "install", "--disable-pip-version-check",
            *definition["pip_specs"],
        ]
        run_checked(pip_command)

    marker.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    return prefix


def conda_command(task: dict[str, Any], command: list[str]) -> list[str]:
    conda = task["conda"]
    return [conda, "run", "--prefix", task["env_prefix"], "--no-capture-output", *command]


def msvc_environment() -> dict[str, str]:
    """Return a copy of the environment initialized for a usable MSVC x64 toolchain.

    Hosted Windows images can contain more than one Visual Studio installation.
    Do not assume the newest one is usable: try every installation that advertises
    the x86/x64 C++ tools, newest first, and retain the diagnostics from failures.
    """
    if os.name != "nt":
        return os.environ.copy()

    roots = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe",
    ]
    vswhere = next((path for path in roots if path.is_file()), None)
    if vswhere is None:
        raise BuildError(
            "MSVC was requested, but vswhere.exe was not found. "
            "The Windows runner needs the Visual C++ build tools."
        )

    query = subprocess.run(
        [
            str(vswhere), "-all", "-products", "*",
            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-format", "json",
        ],
        capture_output=True, text=True, errors="replace",
    )
    if query.returncode != 0:
        raise BuildError(
            "vswhere could not enumerate Visual Studio installations: "
            + (query.stderr.strip() or query.stdout.strip() or f"exit code {query.returncode}")
        )
    try:
        installations = json.loads(query.stdout)
    except json.JSONDecodeError as exc:
        raise BuildError(f"vswhere returned invalid JSON: {exc}") from exc
    if not isinstance(installations, list):
        raise BuildError("vswhere returned an unexpected installation list")

    def version_key(item: dict[str, Any]) -> tuple[int, ...]:
        value = str(item.get("installationVersion", "0"))
        try:
            return tuple(int(part) for part in value.split("."))
        except ValueError:
            return (0,)

    installations = sorted(
        (item for item in installations if isinstance(item, dict) and item.get("installationPath")),
        key=version_key,
        reverse=True,
    )
    if not installations:
        raise BuildError(
            "Visual Studio C++ Build Tools were not found by vswhere. "
            "Install the 'Desktop development with C++' workload."
        )

    comspec = os.environ.get("COMSPEC", "cmd.exe")
    failures: list[str] = []
    for installation in installations:
        install_path = Path(str(installation["installationPath"]))
        vcvars = install_path / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
        label = f"{install_path} (version {installation.get('installationVersion', 'unknown')})"
        if not vcvars.is_file():
            failures.append(f"{label}: vcvarsall.bat is missing")
            continue

        # Keep this as a single cmd.exe command string. CALL is required for
        # a .bat file so that SET runs after vcvarsall returns to this shell.
        command = f'call "{vcvars}" x64 && set'
        result = subprocess.run(
            [comspec, "/d", "/c", command],
            capture_output=True, text=True, errors="replace",
        )
        if result.returncode != 0:
            detail = (result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}")
            failures.append(f"{label}: vcvarsall exited {result.returncode}: {detail[-2500:]}")
            continue

        env = os.environ.copy()
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            # cmd.exe can emit pseudo-variables such as '=C:'; those are not
            # ordinary environment keys and cannot be imported with os.environ.
            if separator and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_()]*", key):
                env[key] = value

        if shutil.which("cl.exe", path=env.get("PATH")) is None:
            failures.append(f"{label}: vcvarsall succeeded but cl.exe is not on PATH")
            continue
        if not env.get("INCLUDE") or not env.get("LIB"):
            failures.append(f"{label}: vcvarsall did not define INCLUDE and LIB")
            continue
        log(f"Using MSVC toolchain: {label}")
        return env

    detail = "\n".join(f"  - {failure}" for failure in failures)
    raise BuildError(
        "Could not initialize an MSVC x64 environment from any Visual Studio "
        "installation. Ensure the Windows runner has the 'Desktop development "
        "with C++' workload and a Windows SDK installed. Attempts:\n" + detail
    )


def copy_tree_contents(source: Path, destination: Path) -> list[Path]:
    copied: list[Path] = []
    if not source.exists():
        return copied
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        target = destination / item.name
        if item.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)
        copied.append(target)
    return copied


def check_artifact_pattern(task: dict[str, Any], output_dir: Path) -> list[Path]:
    config = task["config"]
    artifacts = config.get("artifacts", {})
    if not isinstance(artifacts, dict):
        raise BuildError(f"{task['module']}.artifacts must be an object")
    key = "windows_pattern" if task["platform"] == "windows" else "linux_pattern"
    pattern = artifacts.get(key)
    files = [path for path in output_dir.rglob("*") if path.is_file()]
    if pattern:
        files = [path for path in files if fnmatch.fnmatch(path.name, pattern)]
    if not files:
        expected = f" matching {pattern!r}" if pattern else ""
        raise BuildError(f"{task['module']} ({task['label']}) produced no artifact files{expected}")
    return files


def compiler_args(config: dict[str, Any], compiler: str) -> list[str]:
    value = config.get("compiler_args", [])
    if isinstance(value, dict):
        keys = ["msvc", "windows"] if compiler == "msvc" else ["unix", "gcc", "clang"]
        value = next((value[key] for key in keys if key in value), [])
    return string_list(value, "compiler_args")


def build_native_c_cpp(task: dict[str, Any]) -> list[Path]:
    module = task["module"]
    config = task["config"]
    language = task["language"]
    target = task["target"]
    platform_name = task["platform"]
    output = Path(task["output_dir"])
    work = Path(task["work_dir"])
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.mkdir(parents=True)
    work.mkdir(parents=True)

    sources = existing_sources(module, config.get("sources"))
    section = require_dict(config.get(language, {}), f"{module}.{language}")
    standard = section.get("standard", config.get("cxx_standard", 17) if language == "cpp" else 17)
    if not isinstance(standard, int) or standard < 1:
        raise BuildError(f"{module}.{language}.standard must be a positive integer")
    includes = string_list(section.get("include_dirs", config.get("include_dirs", [])), f"{module}.{language}.include_dirs")
    include_paths = [str(resolve_path(value, f"{module}.include_dirs")) for value in includes]
    for include in include_paths:
        if not Path(include).is_dir():
            raise BuildError(f"Include directory does not exist: {include}")
    compiler_key = "msvc" if platform_name == "windows" else "gcc"
    extra_compile_value = section.get("compiler_args", config.get("compiler_args", []))
    if isinstance(extra_compile_value, dict):
        extra_compile_value = extra_compile_value.get(compiler_key, extra_compile_value.get("unix" if compiler_key == "gcc" else "msvc", []))
    extra_compile = string_list(extra_compile_value, f"{module}.compiler_args")
    extra_link = string_list(section.get("linker_args", config.get("linker_args", [])), f"{module}.linker_args")
    platform_libraries_key = "windows_libraries" if platform_name == "windows" else "linux_libraries"
    legacy_libraries_key = "windows_libraries" if platform_name == "windows" else "unix_libraries"
    library_values = section.get(platform_libraries_key, section.get("libraries", config.get(legacy_libraries_key, [])))
    libraries = string_list(library_values, f"{module}.{language}.libraries")
    output_name = section.get("output_name", config.get("output_name", module))
    require_string(output_name, f"{module}.{language}.output_name")
    if Path(output_name).name != output_name or "/" in output_name or "\\" in output_name:
        raise BuildError(f"{module}.{language}.output_name must be a filename, not a path")
    safe_component(output_name, f"{module}.{language}.output_name")

    extension = {"windows": ".exe", "linux": ""}[platform_name]
    shared_extension = ".dll" if platform_name == "windows" else ".so"
    static_extension = ".lib" if platform_name == "windows" else ".a"
    if target == "executable":
        output_file = output / (output_name + extension)
    elif target == "shared_library":
        output_file = output / (output_name + shared_extension)
    else:
        output_file = output / (output_name + static_extension)

    if platform_name == "windows":
        env = msvc_environment()
        compiler_exe = "cl.exe"
        if target == "static_library":
            compiler_exe = "lib.exe"
        if shutil.which(compiler_exe, path=env.get("PATH")) is None:
            raise BuildError(f"{compiler_exe} was not found after initializing MSVC")
        if target == "static_library":
            objects: list[str] = []
            for index, source in enumerate(sources):
                obj = work / f"source-{index}.obj"
                command = ["cl.exe", "/nologo", "/c", source, f"/Fo{obj}"]
                command.extend(f"/I{path}" for path in include_paths)
                command.extend(extra_compile)
                if language == "c":
                    command.append(f"/std:c{standard}")
                else:
                    command.append(f"/std:c++{standard}")
                run_checked(command, cwd=REPO_ROOT, env=env)
                objects.append(str(obj))
            run_checked(["lib.exe", "/nologo", f"/OUT:{output_file}", *objects], cwd=REPO_ROOT, env=env)
        else:
            command = ["cl.exe", "/nologo", "/O2"]
            if target == "shared_library":
                command.append("/LD")
            command.extend(f"/I{path}" for path in include_paths)
            command.extend(extra_compile)
            command.append(f"/std:c{standard}" if language == "c" else f"/std:c++{standard}")
            command.extend(sources)
            command.append(f"/Fe:{output_file}")
            if libraries or extra_link:
                command.append("/link")
                command.extend(item if item.lower().endswith((".lib", ".obj")) else item + ".lib" for item in libraries)
                command.extend(extra_link)
                if target == "shared_library":
                    command.append(f"/OUT:{output_file}")
            run_checked(command, cwd=REPO_ROOT, env=env)
    else:
        compiler = "cc" if language == "c" else "c++"
        compiler_path = shutil.which(compiler)
        if not compiler_path:
            raise BuildError(f"Required compiler {compiler!r} was not found on PATH")
        if target == "static_library":
            objects = []
            for index, source in enumerate(sources):
                obj = work / f"source-{index}.o"
                command = [compiler_path, f"-std={'c' if language == 'c' else 'c++'}{standard}", "-O2", "-fPIC", "-c", source, "-o", str(obj)]
                command.extend(f"-I{path}" for path in include_paths)
                command.extend(extra_compile)
                run_checked(command, cwd=REPO_ROOT)
                objects.append(str(obj))
            ar = shutil.which("ar")
            if not ar:
                raise BuildError("The 'ar' archiver was not found on PATH")
            run_checked([ar, "rcs", str(output_file), *objects], cwd=REPO_ROOT)
        else:
            command = [compiler_path, f"-std={'c' if language == 'c' else 'c++'}{standard}", "-O2"]
            if target == "shared_library":
                command.extend(["-shared", "-fPIC"])
            command.extend(f"-I{path}" for path in include_paths)
            command.extend(extra_compile)
            command.extend(sources)
            command.extend(["-o", str(output_file)])
            for library in libraries:
                command.append(library if library.startswith("-") else f"-l{library}")
            command.extend(extra_link)
            run_checked(command, cwd=REPO_ROOT)

    return check_artifact_pattern(task, output)


def build_cpp_extension(task: dict[str, Any]) -> list[Path]:
    config = task["config"]
    module = task["module"]
    output = Path(task["output_dir"])
    work = Path(task["work_dir"])
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.mkdir(parents=True)
    work.mkdir(parents=True)

    sources = config.get("_resolved_sources") or existing_sources(module, config.get("sources"))
    module_name = config.get("module_name", module)
    require_string(module_name, f"{module}.module_name")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", module_name):
        raise BuildError(f"{module}.module_name must be a valid dotted Python module name")
    cpp = require_dict(config.get("cpp", {}), f"{module}.cpp")
    standard = cpp.get("standard", config.get("cxx_standard", 17))
    if not isinstance(standard, int) or standard < 11:
        raise BuildError(f"{module}.cpp.standard must be an integer >= 11")
    compiler = "msvc" if task["platform"] == "windows" else "unix"
    extra_compile = compiler_args(cpp, compiler)
    extra_compile.extend(compiler_args(config, compiler))
    extra_compile.append(f"/std:c++{standard}" if compiler == "msvc" else f"-std=c++{standard}")
    include_dirs = string_list(cpp.get("include_dirs", config.get("include_dirs", [])), f"{module}.include_dirs")
    include_paths = [str(resolve_path(value, f"{module}.include_dirs")) for value in include_dirs]
    libraries = string_list(
        cpp.get("windows_libraries" if compiler == "msvc" else "linux_libraries", config.get("windows_libraries" if compiler == "msvc" else "unix_libraries", [])),
        f"{module}.libraries",
    )
    extension_spec = {
        "module_name": module_name,
        "sources": sources,
        "include_dirs": include_paths,
        "libraries": libraries,
        "extra_compile_args": extra_compile,
        "extra_link_args": string_list(cpp.get("linker_args", []), f"{module}.cpp.linker_args"),
        "build_lib": str(work / "raw-lib"),
        "build_temp": str(work / "objects"),
        "distribution_name": str(config.get("distribution_name", module)),
        "parallel": int(task.get("jobs_per_build", 1)),
    }
    spec_path = work / "extension-build.json"
    script_path = work / "run_extension_build.py"
    spec_path.write_text(json.dumps(extension_spec, indent=2), encoding="utf-8")
    script_path.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        "from setuptools import Extension, setup\n"
        "import pybind11\n"
        "spec = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
        "include_dirs = [pybind11.get_include(), *spec['include_dirs']]\n"
        "extension = Extension(spec['module_name'], sources=spec['sources'], "
        "include_dirs=include_dirs, libraries=spec['libraries'], "
        "extra_compile_args=spec['extra_compile_args'], "
        "extra_link_args=spec['extra_link_args'], language='c++')\n"
        "setup(name=spec['distribution_name'], version='0.0.0', "
        "ext_modules=[extension], script_args=['build_ext', '--force', "
        "'--parallel', str(spec['parallel']), '--build-lib', spec['build_lib'], "
        "'--build-temp', spec['build_temp']], "
        "zip_safe=False)\n",
        encoding="utf-8",
    )

    env = None
    if task["platform"] == "windows":
        env = msvc_environment()
    env_command = conda_command(task, ["python", str(script_path), str(spec_path)])
    run_checked(env_command, cwd=REPO_ROOT, env=env)

    raw_lib = work / "raw-lib"
    pattern_key = "windows_pattern" if task["platform"] == "windows" else "linux_pattern"
    artifacts_config = require_dict(config.get("artifacts", {}), f"{module}.artifacts")
    pattern = artifacts_config.get(pattern_key, "*.pyd" if task["platform"] == "windows" else "*.so")
    matches = [path for path in raw_lib.rglob("*") if path.is_file() and fnmatch.fnmatch(path.name, pattern)]
    if not matches:
        raise BuildError(f"{module} built no extension matching {pattern!r} for {task['label']}")
    for source in matches:
        relative = source.relative_to(raw_lib)
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    extension_smoke_test = config.get("smoke_test", True)
    if not isinstance(extension_smoke_test, bool):
        raise BuildError(f"{module}.smoke_test must be true or false")
    if extension_smoke_test:
        smoke_env = os.environ.copy()
        smoke_env["PYTHONPATH"] = str(raw_lib) + (os.pathsep + smoke_env["PYTHONPATH"] if smoke_env.get("PYTHONPATH") else "")
        smoke_code = (
            "import importlib, sys; m=importlib.import_module(sys.argv[1]); "
            "print('Imported extension:', m.__name__)"
        )
        run_checked(conda_command(task, ["python", "-c", smoke_code, module_name]), cwd=raw_lib, env=smoke_env)
    return check_artifact_pattern(task, output)


def build_rust_extension(task: dict[str, Any]) -> list[Path]:
    """Build a PyO3 cdylib against the exact Python interpreter for this task."""
    config = task["config"]
    module = task["module"]
    rust = require_dict(config.get("rust", {}), f"{module}.rust")
    py = require_dict(config.get("python", {}), f"{module}.python")
    manifest_value = config.get("_resolved_manifest") or rust.get("manifest", "Cargo.toml")
    manifest = resolve_path(require_string(manifest_value, f"{module}.rust.manifest"), f"{module}.rust.manifest")
    if not manifest.is_file():
        raise BuildError(f"Rust manifest does not exist: {manifest}")

    try:
        cargo_manifest = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BuildError(f"Could not parse Cargo manifest {manifest}: {exc}") from exc

    package = require_dict(cargo_manifest.get("package", {}), f"{module}.Cargo.toml.package")
    lib_config = require_dict(cargo_manifest.get("lib", {}), f"{module}.Cargo.toml.lib")
    package_name = require_string(package.get("name"), f"{module}.Cargo.toml.package.name")
    lib_name = lib_config.get("name", package_name.replace("-", "_"))
    require_string(lib_name, f"{module}.Cargo.toml.lib.name")
    crate_types = lib_config.get("crate-type", ["lib"])
    if not isinstance(crate_types, list) or any(not isinstance(item, str) for item in crate_types):
        raise BuildError(f"{module}.Cargo.toml.lib.crate-type must be an array of strings")
    if "cdylib" not in crate_types:
        raise BuildError(
            f"{module} is configured as a PyO3 extension, but Cargo.toml [lib].crate-type "
            "does not include 'cdylib'. Set crate-type = [\"cdylib\"] (optionally also 'rlib')."
        )

    if rust.get("target_triple"):
        raise BuildError(
            "rust.target_triple is not supported for PyO3 extension builds: the target Python "
            "ABI must match the interpreter running on this build runner."
        )

    module_name = py.get("module_name", rust.get("module_name", lib_name))
    require_string(module_name, f"{module}.python.module_name")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", module_name):
        raise BuildError(f"{module}.python.module_name must be a valid dotted Python module name")
    module_basename = module_name.rsplit(".", 1)[-1]

    output = Path(task["output_dir"])
    work = Path(task["work_dir"])
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.mkdir(parents=True)
    target_dir = work / "cargo-target"
    target_dir.mkdir(parents=True)

    env_prefix = Path(task["env_prefix"])
    python_executable = env_prefix / ("python.exe" if task["platform"] == "windows" else "bin/python")
    if not python_executable.is_file():
        raise BuildError(f"Python interpreter for this matrix task was not found: {python_executable}")

    probe = (
        "import json,sys,sysconfig; "
        "print(json.dumps({"
        "'major':sys.version_info.major,'minor':sys.version_info.minor,"
        "'gil_disabled':int(sysconfig.get_config_var('Py_GIL_DISABLED') or 0),"
        "'ext_suffix':sysconfig.get_config_var('EXT_SUFFIX')"
        "}))"
    )
    python_info = json.loads(capture_checked(conda_command(task, ["python", "-c", probe]), cwd=REPO_ROOT))
    actual_version = f"{python_info['major']}.{python_info['minor']}"
    expected_version = task.get("python_version")
    if expected_version not in (None, "stable") and actual_version != expected_version:
        raise BuildError(
            f"Conda selected Python {actual_version}, but this task requires Python {expected_version}"
        )
    actual_abi = "free-threaded" if python_info["gil_disabled"] else "gil"
    expected_abi = task.get("abi", "gil")
    if actual_abi != expected_abi:
        raise BuildError(
            f"Conda selected the {actual_abi} ABI, but this task requires {expected_abi}"
        )
    extension_suffix = python_info.get("ext_suffix")
    if not isinstance(extension_suffix, str) or not extension_suffix:
        raise BuildError("The selected Python interpreter did not report a valid EXT_SUFFIX")

    profile = rust.get("profile", "release")
    require_string(profile, f"{module}.rust.profile")
    command = ["cargo", "build", "--manifest-path", str(manifest), "--profile", profile, "--lib"]
    lockfile_exists = (manifest.parent / "Cargo.lock").is_file()
    locked = rust.get("locked", lockfile_exists)
    if not isinstance(locked, bool):
        raise BuildError("rust.locked must be true or false")
    if locked:
        command.append("--locked")
    if rust.get("offline", False):
        command.append("--offline")
    if rust.get("no_default_features", False):
        command.append("--no-default-features")
    if rust.get("all_features", False):
        command.append("--all-features")
    features = string_list(rust.get("features"), "rust.features")
    if features:
        command.extend(["--features", ",".join(features)])

    env = msvc_environment() if task["platform"] == "windows" else os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env["PYO3_PYTHON"] = str(python_executable)
    cargo_jobs = rust.get("jobs", task.get("jobs_per_build", 1))
    if not isinstance(cargo_jobs, int) or cargo_jobs < 1:
        raise BuildError("rust.jobs must be a positive integer")
    env["CARGO_BUILD_JOBS"] = str(cargo_jobs)
    run_checked(conda_command(task, command), cwd=REPO_ROOT, env=env)

    artifact_base = target_dir / profile
    library_file = f"{lib_name}.dll" if task["platform"] == "windows" else f"lib{lib_name}.so"
    built_library = artifact_base / library_file
    if not built_library.is_file():
        produced = [path.name for path in artifact_base.iterdir() if path.is_file()] if artifact_base.exists() else []
        raise BuildError(
            f"Cargo did not produce the PyO3 cdylib {built_library}. "
            f"Files present: {produced}. Check [lib].name and [lib].crate-type in Cargo.toml."
        )

    package_path = Path(*module_name.split(".")[:-1])
    destination_dir = output / package_path
    destination_dir.mkdir(parents=True, exist_ok=True)
    extension_path = destination_dir / (module_basename + extension_suffix)
    shutil.copy2(built_library, extension_path)

    smoke_test = config.get("smoke_test", True)
    if not isinstance(smoke_test, bool):
        raise BuildError(f"{module}.smoke_test must be true or false")
    if smoke_test:
        smoke_env = os.environ.copy()
        smoke_env["PYTHONPATH"] = str(output) + (
            os.pathsep + smoke_env["PYTHONPATH"] if smoke_env.get("PYTHONPATH") else ""
        )
        smoke_code = (
            "import importlib,sys; "
            "m=importlib.import_module(sys.argv[1]); "
            "print('Imported Rust extension:',m.__name__); "
            "check=getattr(sys,'_is_gil_enabled',None); "
            "expected=sys.argv[2]; "
            "assert expected != 'free-threaded' or (check is not None and not check()), "
            "'The extension re-enabled the GIL; update PyO3/module free-threading support.'"
        )
        run_checked(
            conda_command(task, ["python", "-c", smoke_code, module_name, expected_abi]),
            cwd=output,
            env=smoke_env,
        )

    return check_artifact_pattern(task, output)


def build_rust(task: dict[str, Any]) -> list[Path]:
    if task["target"] == "python_extension":
        return build_rust_extension(task)

    config = task["config"]
    rust = require_dict(config.get("rust", {}), f"{task['module']}.rust")
    output = Path(task["output_dir"])
    work = Path(task["work_dir"])
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.mkdir(parents=True)
    target_dir = work / "cargo-target"
    target_dir.mkdir(parents=True)

    manifest = task["config"].get("_resolved_manifest")
    if not manifest:
        manifest_path = resolve_path(require_string(rust.get("manifest", "Cargo.toml"), "rust.manifest"), "rust.manifest")
        manifest = str(manifest_path)
    profile = rust.get("profile", "release")
    require_string(profile, "rust.profile")
    command = ["cargo", "build", "--manifest-path", manifest, "--profile", profile]
    lockfile_exists = (Path(manifest).parent / "Cargo.lock").is_file()
    locked = rust.get("locked", lockfile_exists)
    if not isinstance(locked, bool):
        raise BuildError("rust.locked must be true or false")
    if locked:
        command.append("--locked")
    if rust.get("offline", False):
        command.append("--offline")
    if rust.get("no_default_features", False):
        command.append("--no-default-features")
    if rust.get("all_features", False):
        command.append("--all-features")
    features = string_list(rust.get("features"), "rust.features")
    if features:
        command.extend(["--features", ",".join(features)])
    triple = rust.get("target_triple")
    if triple:
        command.extend(["--target", require_string(triple, "rust.target_triple")])
    bin_name = rust.get("bin")
    if bin_name:
        command.extend(["--bin", require_string(bin_name, "rust.bin")])
    env = msvc_environment() if task["platform"] == "windows" else os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    cargo_jobs = rust.get("jobs", task.get("jobs_per_build", 1))
    if not isinstance(cargo_jobs, int) or cargo_jobs < 1:
        raise BuildError("rust.jobs must be a positive integer")
    env["CARGO_BUILD_JOBS"] = str(cargo_jobs)
    run_checked(conda_command(task, command), cwd=REPO_ROOT, env=env)

    artifact_base = target_dir
    if triple:
        artifact_base = artifact_base / triple
    artifact_base = artifact_base / profile
    output_name = rust.get("output_name", bin_name or task["module"])
    require_string(output_name, "rust.output_name")
    suffix = ".exe" if task["platform"] == "windows" else ""
    candidates = [artifact_base / (output_name + suffix)]
    if bin_name and bin_name != output_name:
        candidates.append(artifact_base / (bin_name + suffix))
    found = next((path for path in candidates if path.is_file()), None)
    if found is None:
        produced = [p for p in artifact_base.iterdir() if p.is_file()] if artifact_base.exists() else []
        raise BuildError(
            f"Cargo succeeded but expected binary {candidates[0]} was not found. "
            f"Files present: {[p.name for p in produced]} (set rust.bin/output_name to the Cargo binary name)."
        )
    shutil.copy2(found, output / (output_name + suffix))
    return check_artifact_pattern(task, output)


def build_go(task: dict[str, Any]) -> list[Path]:
    go = require_dict(task["config"].get("go", {}), f"{task['module']}.go")
    output = Path(task["output_dir"])
    work = Path(task["work_dir"])
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.mkdir(parents=True)
    work.mkdir(parents=True)
    output_name = go.get("output_name", task["module"])
    require_string(output_name, "go.output_name")
    safe_component(output_name, "go.output_name")
    suffix = ".exe" if task["platform"] == "windows" else ""
    binary = output / (output_name + suffix)
    package = require_string(go.get("package", "."), "go.package")
    if go.get("cgo", False) and task["platform"] == "windows":
        raise BuildError("Go CGO builds on Windows need a separately configured MinGW toolchain; this backend currently supports CGO on Linux only")
    command = ["go", "build"]
    go_jobs = go.get("jobs", task.get("jobs_per_build", 1))
    if not isinstance(go_jobs, int) or go_jobs < 1:
        raise BuildError("go.jobs must be a positive integer")
    command.extend(["-p", str(go_jobs)])
    if go.get("trimpath", True):
        command.append("-trimpath")
    if go.get("build_mode"):
        command.extend(["-buildmode", require_string(go["build_mode"], "go.build_mode")])
    tags = string_list(go.get("build_tags"), "go.build_tags")
    if tags:
        command.extend(["-tags", ",".join(tags)])
    ldflags = go.get("ldflags")
    if ldflags:
        command.extend(["-ldflags", require_string(ldflags, "go.ldflags")])
    command.extend(["-o", str(binary), package])
    env = os.environ.copy()
    env["GOCACHE"] = str(work / "go-cache")
    env["GOOS"] = str(go.get("goos", "windows" if task["platform"] == "windows" else "linux"))
    machine = platform.machine().lower()
    goarch_default = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
    env["GOARCH"] = str(go.get("goarch", goarch_default))
    env["CGO_ENABLED"] = "1" if go.get("cgo", False) else "0"
    run_checked(conda_command(task, command), cwd=REPO_ROOT, env=env)
    return check_artifact_pattern(task, output)


def add_path_args(command: list[str], option: str, values: list[str]) -> None:
    for value in values:
        command.extend([option, value])


def build_python_app(task: dict[str, Any]) -> list[Path]:
    py = require_dict(task["config"].get("python", {}), f"{task['module']}.python")
    output = Path(task["output_dir"])
    work = Path(task["work_dir"])
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.mkdir(parents=True)
    work.mkdir(parents=True)
    entry = py.get("_resolved_entry")
    if not entry:
        entry = str(resolve_path(require_string(py.get("entry"), "python.entry"), "python.entry"))
    packager = py.get("packager", "pyinstaller")
    name = py.get("name", task["module"])
    require_string(name, "python.name")
    safe_component(name, "python.name")
    onefile = py.get("onefile", True)
    if not isinstance(onefile, bool):
        raise BuildError("python.onefile must be true or false")
    if "smoke_test" in py and not isinstance(py["smoke_test"], bool):
        raise BuildError("python.smoke_test must be true or false")

    if packager == "pyinstaller":
        dist = work / "pyinstaller-dist"
        command = [
            "pyinstaller", "--noconfirm", "--clean", "--name", name,
            "--distpath", str(dist), "--workpath", str(work / "pyinstaller-work"),
            "--specpath", str(work / "pyinstaller-spec"),
        ]
        command.append("--onefile" if onefile else "--onedir")
        if py.get("console", True) is False:
            command.append("--windowed")
        for key, option in (("hidden_imports", "--hidden-import"), ("collect_all", "--collect-all"), ("collect_data", "--collect-data"), ("collect_binaries", "--collect-binaries"), ("paths", "--paths")):
            add_path_args(command, option, string_list(py.get(key), f"python.{key}"))
        for item in py.get("add_data", []):
            if not isinstance(item, dict):
                raise BuildError("python.add_data entries must be objects with source and destination")
            source = require_string(item.get("source"), "python.add_data.source")
            destination = require_string(item.get("destination"), "python.add_data.destination", allow_empty=True)
            source_path = resolve_path(source, "python.add_data.source")
            command.extend(["--add-data", f"{source_path}{os.pathsep}{destination}"])
        icon = py.get("icon")
        if icon:
            command.extend(["--icon", str(resolve_path(require_string(icon, "python.icon"), "python.icon"))])
        command.extend(string_list(py.get("extra_args"), "python.extra_args"))
        command.append(entry)
        run_checked(conda_command(task, command), cwd=REPO_ROOT)
        if not dist.exists():
            raise BuildError("PyInstaller completed without creating its dist directory")
        copy_tree_contents(dist, output)

    elif packager == "nuitka":
        dist = work / "nuitka-output"
        dist.mkdir(parents=True, exist_ok=True)
        command = [
            "python", "-m", "nuitka", "--assume-yes-for-downloads",
            f"--output-dir={dist}", f"--output-filename={name}",
            f"--jobs={task.get('jobs_per_build', 1)}",
        ]
        command.append("--onefile" if onefile else "--standalone")
        if py.get("follow_imports", True):
            command.append("--follow-imports")
        if py.get("console", True) is False and task["platform"] == "windows":
            command.append("--windows-console-mode=disable")
        for value in string_list(py.get("include_modules"), "python.include_modules"):
            command.append(f"--include-module={value}")
        for value in string_list(py.get("include_packages"), "python.include_packages"):
            command.append(f"--include-package={value}")
        for item in py.get("include_data_dirs", []):
            if not isinstance(item, dict):
                raise BuildError("python.include_data_dirs entries must be objects with source and destination")
            source = resolve_path(require_string(item.get("source"), "python.include_data_dirs.source"), "python.include_data_dirs.source")
            destination = require_string(item.get("destination"), "python.include_data_dirs.destination")
            command.append(f"--include-data-dir={source}={destination}")
        command.extend(string_list(py.get("extra_args"), "python.extra_args"))
        command.append(entry)
        nuitka_env = msvc_environment() if task["platform"] == "windows" else None
        run_checked(conda_command(task, command), cwd=REPO_ROOT, env=nuitka_env)

        # Nuitka may emit a one-file binary or a standalone .dist directory.
        candidates = list(dist.iterdir())
        dist_dirs = [path for path in candidates if path.is_dir() and path.name.endswith(".dist")]
        if dist_dirs:
            for directory in dist_dirs:
                destination = output / directory.name
                shutil.copytree(directory, destination)
        binaries = [path for path in candidates if path.is_file() and (path.name == name or path.name == name + ".exe" or path.name.startswith(name + "."))]
        for binary in binaries:
            shutil.copy2(binary, output / binary.name)
        if not dist_dirs and not binaries:
            raise BuildError(f"Nuitka did not produce an identifiable binary or .dist directory in {dist}")
    else:
        raise BuildError(f"Unknown Python packager: {packager!r}")

    files = [path for path in output.rglob("*") if path.is_file()]
    if not files:
        raise BuildError(f"Python packager produced no files for {task['module']} ({task['label']})")

    smoke_args = string_list(py.get("smoke_test_args"), "python.smoke_test_args")
    if py.get("smoke_test", False) and onefile:
        executable = next((p for p in files if p.name == name or p.name == name + ".exe"), None)
        if executable and smoke_args:
            run_checked([str(executable), *smoke_args], cwd=output)
    return check_artifact_pattern(task, output)


def execute_task(task: dict[str, Any]) -> dict[str, Any]:
    task = dict(task)
    conda = task.pop("_conda", None)
    if conda is not None:
        task["conda"] = conda
    task_name = f"{task['module']} / {task['label']} / {task['language']}"
    start = time.time()
    log(f"START {task_name}")
    try:
        if task["language"] in {"c", "cpp"} and task["target"] != "python_extension":
            files = build_native_c_cpp(task)
        elif task["language"] == "cpp" and task["target"] == "python_extension":
            files = build_cpp_extension(task)
        elif task["language"] == "rust":
            files = build_rust(task)
        elif task["language"] == "go":
            files = build_go(task)
        elif task["language"] == "python":
            files = build_python_app(task)
        else:
            raise BuildError(f"No backend for {task['language']} / {task['target']}")
        elapsed = time.time() - start
        log(f"SUCCESS {task_name} ({len(files)} artifact file(s), {elapsed:.1f}s)")
        return {"ok": True, "task": task_name, "files": [str(path) for path in files], "seconds": elapsed}
    except Exception as exc:
        elapsed = time.time() - start
        detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        log(f"FAILED {task_name} ({elapsed:.1f}s): {exc}")
        return {"ok": False, "task": task_name, "error": str(exc), "traceback": detail, "seconds": elapsed}


def run_group(group: dict[str, Any]) -> list[dict[str, Any]]:
    # A worker owns one environment group. It runs those tasks sequentially,
    # preventing simultaneous commands from mutating/using the same env.
    results = []
    for task in group["tasks"]:
        results.append(execute_task(task))
    return results


def write_matrix_metadata(output_root: Path, platform_name: str) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    metadata = {
        "platform": platform_name,
        "os": platform.platform(),
        "python": sys.version,
        "architecture": platform.machine(),
        "created_at": time.time(),
    }
    (output_root / "_matrix.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


def group_tasks(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for task in tasks:
        key = task["resource_key"]
        groups.setdefault(key, {"key": key, "tasks": []})["tasks"].append(task)
    return list(groups.values())


def perform_build(
    config_path: Path,
    output_root: Path,
    env_root_override: Path | None,
    workers_override: int | None,
    temp_root_override: Path | None,
    dry_run: bool,
    module_filter: str | None,
) -> int:
    settings, modules = load_config(config_path)
    if module_filter is not None:
        if module_filter not in modules:
            raise BuildError(f"Unknown module {module_filter!r}. Configured modules: {', '.join(modules)}")
        modules = {module_filter: modules[module_filter]}
    platform_name = current_platform()
    max_workers = workers_override if workers_override is not None else settings.get("max_workers", 4)
    if not isinstance(max_workers, int) or max_workers < 1:
        raise BuildError("settings.max_workers must be a positive integer")
    max_workers = min(max_workers, 4)

    channels = string_list(settings.get("conda_channels", ["conda-forge"]), "settings.conda_channels")
    if not channels:
        raise BuildError("settings.conda_channels must not be empty")
    env_setting = settings.get("environment_directory", "build/environments")
    env_root = env_root_override or resolve_path(require_string(str(env_setting), "settings.environment_directory"), "settings.environment_directory")
    temp_setting = settings.get("temporary_directory", "build/temp")
    temp_root = temp_root_override or resolve_path(require_string(str(temp_setting), "settings.temporary_directory"), "settings.temporary_directory")

    tasks, environments, skipped = plan_tasks(modules, platform_name, output_root, temp_root, channels)
    log(f"Platform: {platform_name}; configured modules: {len(modules)}; build targets: {len(tasks)}; environments: {len(environments)}; workers: {max_workers}")
    for module in skipped:
        log(f"SKIP {module}: not configured for {platform_name}")
    for task in tasks:
        env_text = task["env"]["id"] if task["env"] else "native"
        log(f"PLAN {task['module']} / {task['label']} ({task['language']}/{task['target']}; env={env_text})")

    if dry_run:
        log("Dry run: no files were deleted, no Conda environments were created, and no compilers were invoked.")
        return 0

    # Never recursively clean the repository root (or one of its parents), and
    # keep output and intermediate trees disjoint.
    repo = REPO_ROOT.resolve()
    output_root = output_root.resolve()
    temp_root = temp_root.resolve()
    env_root = env_root.resolve()
    for candidate, label in ((output_root, "output"), (temp_root, "temporary"), (env_root, "environment")):
        if candidate == repo or candidate in repo.parents:
            raise BuildError(f"Refusing to use a {label} directory that is the repository root or one of its parents: {candidate}")
    named_paths = [(output_root, "output"), (temp_root, "temporary"), (env_root, "environment")]
    for index, (left, left_name) in enumerate(named_paths):
        for right, right_name in named_paths[index + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise BuildError(f"Output, temporary, and environment directories must be separate; {left_name} and {right_name} overlap")
    if output_root.exists():
        shutil.rmtree(output_root)
    if temp_root.exists():
        shutil.rmtree(temp_root)
    temp_root.mkdir(parents=True, exist_ok=True)
    write_matrix_metadata(output_root, platform_name)

    if not tasks:
        log("No build targets are configured for this platform.")
        return 0

    conda = resolve_conda() if environments else None
    prepared: dict[str, Path] = {}
    if environments:
        env_root.mkdir(parents=True, exist_ok=True)
    # Environment preparation is intentionally sequential: concurrent Conda
    # creates can contend for package-cache locks and prefix state.
    for fingerprint, definition in environments.items():
        assert conda is not None
        prepared[fingerprint] = prepare_environment(conda, definition, env_root)

    for task in tasks:
        if task["env"]:
            assert conda is not None
            task["env_prefix"] = str(prepared[task["env"]["fingerprint"]])
            task["_conda"] = conda

    groups = group_tasks(tasks)
    worker_count = min(max_workers, len(groups))
    jobs_per_build = max(1, (os.cpu_count() or 1) // worker_count)
    for task in tasks:
        task["jobs_per_build"] = jobs_per_build
    # The same task objects are held by the grouped work items.
    log(f"Starting {len(groups)} independent worker group(s) with max_workers={worker_count}; internal jobs per build={jobs_per_build}")
    results: list[dict[str, Any]] = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(run_group, group) for group in groups]
        for future in concurrent.futures.as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as exc:
                results.append({"ok": False, "task": "worker group", "error": str(exc), "traceback": traceback.format_exc()})

    failures = [result for result in results if not result["ok"]]
    summary = {
        "platform": platform_name,
        "total": len(results),
        "succeeded": len(results) - len(failures),
        "failed": len(failures),
        "tasks": results,
    }
    (output_root / "_build-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    log(f"Build summary: {summary['succeeded']} succeeded, {summary['failed']} failed")
    if failures:
        for failure in failures:
            log(f"ERROR {failure['task']}: {failure['error']}")
        return 1
    return 0


def perform_validate(config_path: Path) -> int:
    settings, modules = load_config(config_path)
    platform_name = current_platform()
    tasks, environments, skipped = plan_tasks(
        modules,
        platform_name,
        Path("<output>"),
        Path("<temporary>"),
        string_list(settings.get("conda_channels", ["conda-forge"]), "settings.conda_channels"),
    )
    print(f"Configuration valid: {len(modules)} modules, {len(tasks)} build targets, {len(environments)} environment(s) on {platform_name}.")
    for task in tasks:
        print(f"  {task['module']}: {task['language']}/{task['target']} [{task['label']}]")
    for module in skipped:
        print(f"  {module}: skipped on {platform_name}")
    return 0


def perform_list(config_path: Path) -> int:
    _, modules = load_config(config_path)
    for module_key, config in modules.items():
        language = normalized_language(config)
        target = normalized_target(language, config)
        print(f"{module_key}: {language} / {target}")
    return 0


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Config-driven C/C++/Rust/Go/Python build engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="prepare environments and compile configured targets")
    build_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    build_parser.add_argument("--output", type=Path, default=Path("dist/builds"))
    build_parser.add_argument("--env-dir", type=Path, default=None)
    build_parser.add_argument("--temp-dir", type=Path, default=None)
    build_parser.add_argument("--workers", type=int, default=None)
    build_parser.add_argument("--module", type=str, default=None, help="build only this configured module")
    build_parser.add_argument("--dry-run", action="store_true")

    validate_parser = subparsers.add_parser("validate", help="validate configuration and print its build plan")
    validate_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)

    list_parser = subparsers.add_parser("list", help="list configured modules")
    list_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        config_path = args.config.resolve()
        if args.command == "build":
            output = args.output.resolve()
            env_dir = args.env_dir.resolve() if args.env_dir else None
            temp_dir = args.temp_dir.resolve() if args.temp_dir else None
            return perform_build(config_path, output, env_dir, args.workers, temp_dir, args.dry_run, args.module)
        if args.command == "validate":
            return perform_validate(config_path)
        if args.command == "list":
            return perform_list(config_path)
        parser.error("Unknown command")
    except (BuildError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f"BUILD ERROR: {exc}", file=sys.stderr, flush=True)
        if isinstance(exc, subprocess.CalledProcessError):
            print(f"Command exited with status {exc.returncode}: {exc.cmd}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
