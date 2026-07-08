from pathlib import Path
from jinja2 import Environment, FileSystemLoader


TEMPLATE_DIR = "templates"

OUTPUT_DIR = "output"


def generate_html_report(data):

    env = Environment(

        loader=FileSystemLoader(
            TEMPLATE_DIR
        )

    )

    template = env.get_template(
        "reports/report_template.html"
    )

    html = template.render(data)

    Path(OUTPUT_DIR).mkdir(
        exist_ok=True
    )

    output_file = Path(
        OUTPUT_DIR
    ) / "incident_report.html"

    output_file.write_text(
        html,
        encoding="utf-8"
    )

    return output_file