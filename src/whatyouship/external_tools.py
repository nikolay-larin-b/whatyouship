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
    :param linux_package: Package name used by supported Linux families.
    :param homebrew_formula: Homebrew formula used on macOS.
    :param windows_url: Official Windows download or installation page.
    """

    name: str
    executables: tuple[str, ...]
    linux_package: str
    homebrew_formula: str
    windows_url: str


SEVEN_ZIP = ExternalTool(
    name="7-Zip",
    executables=("7zz", "7z", "7z.exe"),
    linux_package="7zip",
    homebrew_formula="sevenzip",
    windows_url="https://www.7-zip.org/download.html",
)
INNOEXTRACT = ExternalTool(
    name="innoextract",
    executables=("innoextract",),
    linux_package="innoextract",
    homebrew_formula="innoextract",
    windows_url="https://constexpr.org/innoextract/",
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


def _installation_instruction(tool: ExternalTool) -> str:
    """Build an installation instruction for the current operating system.

    :param tool: Missing external tool.
    :returns: Platform-specific installation instruction.
    """
    if sys.platform == "win32":
        return f"Download and install it from {tool.windows_url}."
    if sys.platform == "darwin":
        return f"Install it with Homebrew: brew install {tool.homebrew_formula}."
    if sys.platform.startswith("linux"):
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
    return f"Install {tool.name} and add it to PATH."


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
        f"{_installation_instruction(tool)} Ensure {names} is available in PATH."
    )
