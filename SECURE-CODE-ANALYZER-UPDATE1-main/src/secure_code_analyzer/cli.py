import argparse
import os
import sys

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from secure_code_analyzer.core.scanner import scan_file
from secure_code_analyzer.core.reporters import (
    generate_json_report,
    generate_html_report,
)

# Default reports directory
REPORTS_DIR = os.path.abspath("reports")


def collect_files(paths):
    """
    Collect all .js and .php files from given paths.
    Supports both individual files and directories.
    """
    files = []
    for path in paths:
        if os.path.isfile(path):
            if path.endswith((".js", ".php")):
                files.append(path)
        elif os.path.isdir(path):
            for root, _, filenames in os.walk(path):
                for fname in filenames:
                    if fname.endswith((".js", ".php")):
                        files.append(os.path.join(root, fname))
        else:
            print(f"[WARNING] {path} does not exist, skipping.")
    return files


def run_scan(files_to_scan):
    """Run scan on given files and return list of issues."""
    all_issues = []
    for file in files_to_scan:
        try:
            issues = scan_file(file)
            if issues:
                print(f"\nFound {len(issues)} issues in {file}:")
                for issue in issues:
                    print(
                        f"  [{issue['severity']}] {issue['file']}:{issue['line']} - {issue['message']}"
                    )
                all_issues.extend(issues)
            else:
                print(f"\nNo issues found in {file}")
        except Exception as e:
            print(f"\n[ERROR] Could not scan {file}: {e}")
            all_issues.append(
                {
                    "severity": "LOW",
                    "file": file,
                    "line": 0,
                    "message": f"Error reading file: {e}",
                }
            )
    return all_issues


def cli_mode(args):
    """Run in classic CLI mode."""
    files_to_scan = collect_files(args.targets)
    if not files_to_scan:
        print("❌ No .js or .php files found to scan.")
        sys.exit(1)

    all_issues = run_scan(files_to_scan)

    print("\n=== SCAN COMPLETE ===")
    print(f"Total Issues Found: {len(all_issues)} across {len(files_to_scan)} files")

    if all_issues:
        # Save reports
        os.makedirs(REPORTS_DIR, exist_ok=True)
        json_path = os.path.join(REPORTS_DIR, "report.json")
        html_path = os.path.join(REPORTS_DIR, "report.html")
        generate_json_report(all_issues, json_path)
        generate_html_report(all_issues, html_path)
        print(f"[+] JSON report saved to {json_path}")
        print(f"[+] HTML report saved to {html_path}")


def serve_mode():
    """Run Flask server for frontend integration."""
    app = Flask(__name__)
    CORS(app)

    @app.route("/scan", methods=["POST"])
    def scan_endpoint():
        """
        Upload and scan files via API.
        Expects files in multipart form-data.
        """
        if "files" not in request.files:
            return jsonify({"error": "No files uploaded"}), 400

        uploaded_files = request.files.getlist("files")
        filepaths = []

        os.makedirs("uploads", exist_ok=True)
        for f in uploaded_files:
            path = os.path.join("uploads", f.filename)
            f.save(path)
            filepaths.append(path)

        issues = run_scan(filepaths)

        # Save reports for frontend
        os.makedirs(REPORTS_DIR, exist_ok=True)
        json_path = os.path.join(REPORTS_DIR, "report.json")
        html_path = os.path.join(REPORTS_DIR, "report.html")
        generate_json_report(issues, json_path)
        generate_html_report(issues, html_path)

        return jsonify({"issues": issues, "count": len(issues)})

    @app.route("/reports/<path:filename>", methods=["GET"])
    def serve_reports(filename):
        """Serve saved reports to frontend."""
        return send_from_directory(REPORTS_DIR, filename)

    @app.route("/refresh", methods=["POST"])
    def refresh_scan():
        """Re-run scan on last uploaded files."""
        upload_dir = "uploads"
        if not os.path.exists(upload_dir):
            return jsonify({"error": "No uploaded files to rescan"}), 400

        filepaths = [
            os.path.join(upload_dir, f) for f in os.listdir(upload_dir)
        ]
        issues = run_scan(filepaths)

        # Save updated reports
        json_path = os.path.join(REPORTS_DIR, "report.json")
        html_path = os.path.join(REPORTS_DIR, "report.html")
        generate_json_report(issues, json_path)
        generate_html_report(issues, html_path)

        return jsonify({"issues": issues, "count": len(issues)})

    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Secure Code Analyzer server running at http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)


def main():
    parser = argparse.ArgumentParser(description="Secure Code Analyzer CLI + Server")
    parser.add_argument(
        "targets",
        nargs="*",
        help="Files or directories to scan (for CLI mode)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Run as server instead of CLI mode",
    )

    args = parser.parse_args()

    if args.serve:
        serve_mode()
    else:
        cli_mode(args)


if __name__ == "__main__":
    main()