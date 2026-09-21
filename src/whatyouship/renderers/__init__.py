# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Select a renderer for structured release reports."""

from typing import Literal

from whatyouship.report import Report
from whatyouship.renderers.csv import render_csv
from whatyouship.renderers.json import render_json
from whatyouship.renderers.text import render_text


OutputFormat = Literal["text", "json", "csv"]


def render_report(report: Report, output_format: OutputFormat) -> str:
    """Render a structured report in the requested format.

    :param report: Analysis result to render.
    :param output_format: Text, JSON, or CSV.
    :returns: Complete encoded report text.
    :raises ValueError: If the format or command-format pair is unsupported.
    """
    if output_format == "text":
        return render_text(report)
    if output_format == "json":
        return render_json(report)
    if output_format == "csv":
        return render_csv(report)
    raise ValueError(f"Unsupported output format: {output_format}")
