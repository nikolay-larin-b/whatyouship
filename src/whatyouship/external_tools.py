# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Find required external tools and explain how to install them."""

import platform
import sys
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ExternalTool:
    """Describe an external command and its platform packages.

    :param name: Human-readable tool name.
    :param executables: Supported executable names in lookup order.
    :param download_url: Official download or installation page.
    :param linux_package: Package name used by supported Linux families.
    :param homebrew_formula: Homebrew formula used on macOS.
    :param cargo_package: Cargo package providing the executable.
    """

    name: str
    executables: tuple[str, ...]
    download_url: str
    linux_package: str | None = None
    homebrew_formula: str | None = None
    cargo_package: str | None = None


SEVEN_ZIP = ExternalTool(
    name="7-Zip",
    executables=("7zz", "7z", "7z.exe"),
    download_url="https://www.7-zip.org/download.html",
    linux_package="7zip",
    homebrew_formula="sevenzip",
)
INNOEXTRACT = ExternalTool(
    name="innoextract",
    executables=("innoextract",),
    download_url="https://constexpr.org/innoextract/",
    linux_package="innoextract",
    homebrew_formula="innoextract",
)
RCODESIGN = ExternalTool(
    name="rcodesign",
    executables=("rcodesign", "rcodesign.exe"),
    download_url="https://github.com/indygreg/apple-platform-rs/releases",
    cargo_package="apple-codesign",
)


def _linux_distribution_ids() -> set[str]:
    """Return normalized Linux distribution and family identifiers.

    :returns: Values from the freedesktop ``ID`` and ``ID_LIKE`` fields.
    """
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return set()
    return {
        value.lower()
        for value in (release.get("ID", ""), *release.get("ID_LIKE", "").split())
        if value
    }


def installation_instruction(tool: ExternalTool) -> str:
    """Build an installation instruction for the current operating system.

    :param tool: Missing external tool.
    :returns: Platform-specific installation instruction.
    """
    if tool.cargo_package is not None:
        platform_name = (
            "Windows" if sys.platform == "win32" else
            "macOS" if sys.platform == "darwin" else
            "Linux" if sys.platform.startswith("linux") else
            "your operating system"
        )
        return (
            f"Download the {platform_name} binary from {tool.download_url}, or "
            f"install it with Cargo: cargo install {tool.cargo_package}."
        )
    if sys.platform == "win32":
        return f"Download and install it from {tool.download_url}."
    if sys.platform == "darwin" and tool.homebrew_formula is not None:
        return f"Install it with Homebrew: brew install {tool.homebrew_formula}."
    if sys.platform.startswith("linux") and tool.linux_package is not None:
        distribution_ids = _linux_distribution_ids()
        if distribution_ids & {"debian", "ubuntu"}:
            return f"Install it with: sudo apt install {tool.linux_package}."
        if "fedora" in distribution_ids:
            return f"Install it with: sudo dnf install {tool.linux_package}."
        if distribution_ids & {"arch", "manjaro"}:
            return f"Install it with: sudo pacman -S {tool.linux_package}."
        return (
            "Install it with your system package manager "
            f"(package: {tool.linux_package})."
        )
    return f"Download and install it from {tool.download_url}."


def _executable_list(executables: tuple[str, ...]) -> str:
    """Format executable alternatives for a diagnostic message.

    :param executables: Supported executable names.
    :returns: Quoted, human-readable alternatives.
    """
    quoted = [f"'{executable}'" for executable in executables]
    if len(quoted) == 1:
        return quoted[0]
    return f"{', '.join(quoted[:-1])}, or {quoted[-1]}"


def find_external_tool(
    tool: ExternalTool,
    purpose: str,
    which: Callable[[str], str | None],
) -> str:
    """Find a required external tool or raise an actionable error.

    :param tool: Tool names and installation metadata.
    :param purpose: Operation that requires the tool.
    :param which: Executable lookup function, normally :func:`shutil.which`.
    :returns: Resolved executable path.
    :raises FileNotFoundError: If no supported executable is on ``PATH``.
    """
    for executable_name in tool.executables:
        executable = which(executable_name)
        if executable is not None:
            return executable
    names = _executable_list(tool.executables)
    raise FileNotFoundError(
        f"{tool.name} was not found in PATH. It is required to {purpose}. "
        f"{installation_instruction(tool)} Ensure {names} is available in PATH."
    )
