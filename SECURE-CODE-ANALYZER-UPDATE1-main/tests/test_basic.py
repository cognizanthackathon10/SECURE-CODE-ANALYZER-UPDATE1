import pathlib, json, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from src.secure_code_analyzer.core.scanner import scan_paths

def test_scan_samples_has_findings():
    repo = pathlib.Path(__file__).resolve().parents[1]
    results = scan_paths([str(repo / "samples")])
    assert any(r for r in results), "Expected at least one finding in samples"
