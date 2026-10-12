# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Internal errors raised while analyzing recognized binary files."""


class BinaryAnalysisError(Exception):
    """Report an expected analysis failure for a recognized binary format.

    :param binary_format: Recognized binary format.
    :param reason: Human-readable reason why analysis failed.
    """

    def __init__(self, binary_format: str, reason: str) -> None:
        self.binary_format = binary_format
        self.reason = reason
        super().__init__(f"Unable to analyze {binary_format} binary: {reason}")
