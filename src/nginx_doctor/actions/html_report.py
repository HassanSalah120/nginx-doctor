import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from nginx_doctor.model.server import ServerModel
from nginx_doctor.model.finding import Finding

class HTMLReportAction:
    """Action to generate a user-friendly HTML diagnostic report."""

    def __init__(self, template_dir: str | None = None) -> None:
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.template = self.env.get_template("report.html")

    def generate(
        self, 
        model: ServerModel, 
        findings: list[Finding] = None, 
        output_path: str = "report.html",
        unreferenced: list = None,
        static_noise: list = None,
        ws_inventory: list = None
    ) -> str:
        """Generate the HTML report and save it to a file.
        
        Returns:
            The absolute path of the generated report.
        """
        html_content = self.template.render(
            model=model,
            findings=findings or [],
            unreferenced=unreferenced or [],
            static_noise=static_noise or [],
            ws_inventory=ws_inventory or [],
            now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return os.path.abspath(output_path)
