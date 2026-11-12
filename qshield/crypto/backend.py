"""Central access and validation for QShield's liboqs backend.

This module keeps algorithm names and backend checks in one place so that
other QShield modules do not each implement their own OQS availability logic.
"""

from importlib import import_module, metadata
import os
from pathlib import Path
import platform
import sys
from types import ModuleType

KEM_ALGORITHM = "ML-KEM-768"
SIGNATURE_ALGORITHM = "ML-DSA-65"


class BackendUnavailableError(RuntimeError):
    """Raised when the required post-quantum backend is unavailable."""


def _ensure_windows_dll_path() -> None:
    """Ensure Windows Python runtime can discover native liboqs DLLs."""
    if platform.system() != "Windows":
        return

    candidate_dirs = [
        os.environ.get("OQS_INSTALL_PATH"),
        r"C:\liboqs\build-0160\bin\Release",
        r"C:\liboqs\build-0160\bin",
        str(Path.home() / "_oqs" / "bin"),
        str(Path.home() / "_oqs"),
        r"C:\liboqs\build\bin\Release",
        r"C:\liboqs\build\bin",
    ]

    for directory in reversed(candidate_dirs):
        if directory and os.path.isdir(directory):
            if hasattr(os, "add_dll_directory"):
                try:
                    os.add_dll_directory(directory)
                except OSError:
                    pass
            current_path = os.environ.get("PATH", "")
            if directory not in current_path:
                os.environ["PATH"] = directory + os.pathsep + current_path

    if "OQS_INSTALL_PATH" not in os.environ:
        build_0160 = Path(r"C:\liboqs\build-0160")
        if (build_0160 / "bin" / "Release" / "oqs.dll").exists() or (build_0160 / "bin" / "oqs.dll").exists():
            os.environ["OQS_INSTALL_PATH"] = str(build_0160)
        else:
            home_oqs = Path.home() / "_oqs"
            if (home_oqs / "bin" / "oqs.dll").exists():
                os.environ["OQS_INSTALL_PATH"] = str(home_oqs)


def get_oqs() -> ModuleType:
    """Import liboqs-python and verify QShield's required algorithms.

    Returns:
        The imported oqs module.

    Raises:
        BackendUnavailableError: If the binding cannot load or either
            configured algorithm is not enabled in the native liboqs build.
    """
    _ensure_windows_dll_path()
    try:
        oqs = import_module("oqs")
    except (ImportError, OSError, RuntimeError) as exc:
        raise BackendUnavailableError(
            "Unable to load liboqs-python. Install the package and ensure "
            "the native liboqs shared library is available."
        ) from exc

    try:
        enabled_kems = oqs.get_enabled_kem_mechanisms()
        enabled_signatures = oqs.get_enabled_sig_mechanisms()
    except (AttributeError, OSError, RuntimeError) as exc:
        raise BackendUnavailableError(
            "The loaded OQS binding does not expose the expected algorithm "
            "discovery API."
        ) from exc

    missing = []
    if KEM_ALGORITHM not in enabled_kems:
        missing.append(KEM_ALGORITHM)
    if SIGNATURE_ALGORITHM not in enabled_signatures:
        missing.append(SIGNATURE_ALGORITHM)

    if missing:
        raise BackendUnavailableError(
            "Required algorithms are not enabled in liboqs: "
            + ", ".join(missing)
        )

    return oqs


def backend_info() -> dict[str, str]:
    """Return the provider version and QShield's required algorithm names."""
    get_oqs()  # Fail early if the native backend or algorithms are unavailable.

    try:
        version = metadata.version("liboqs-python")
    except metadata.PackageNotFoundError as exc:
        raise BackendUnavailableError(
            "The liboqs-python package metadata is not installed."
        ) from exc

    return {
        "provider": "liboqs-python",
        "version": version,
        "kem": KEM_ALGORITHM,
        "signature": SIGNATURE_ALGORITHM,
        "status": "available",
    }
