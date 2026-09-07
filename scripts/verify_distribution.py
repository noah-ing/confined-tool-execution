"""Check the wheel contains only runtime code and distribution metadata."""

from pathlib import Path
from zipfile import ZipFile


def main() -> None:
    distributions = list(Path("dist").glob("*.whl"))
    if len(distributions) != 1:
        raise RuntimeError("exactly_one_wheel_required")
    with ZipFile(distributions[0]) as distribution:
        members = distribution.namelist()
    if not any(name.endswith("confined_tool_execution/supervisor.py") for name in members):
        raise RuntimeError("runtime_missing_from_distribution")
    for name in members:
        if not name.startswith("confined_tool_execution/") and ".dist-info/" not in name:
            raise RuntimeError("nonruntime_file_in_distribution")
        if name.endswith((".jsonl", ".key", ".pem", ".log")):
            raise RuntimeError("generated_material_in_distribution")
    print("Wheel contains runtime code and distribution metadata only.")


if __name__ == "__main__":
    main()
