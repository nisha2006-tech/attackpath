import html
import json
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def _level(score):
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def write_html(ranked, out_path, source, host_count):
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    paths = []
    for r in ranked:
        item = dict(r)
        item["level"] = _level(r["score"])
        paths.append(item)
    page = env.get_template("report.html").render(
        paths=paths, source=source, host_count=host_count,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"))
    Path(out_path).write_text(page, encoding="utf-8")


def write_json(ranked, out_path):
    Path(out_path).write_text(json.dumps(ranked, indent=2), encoding="utf-8")
