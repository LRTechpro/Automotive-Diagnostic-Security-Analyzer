from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .analyzer import analyze
from .parser import TraceFormatError, load_trace
from .reporting import export_reports


class AnalyzerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Automotive Diagnostic Security Analyzer")
        self.geometry("1100x650")
        self.minsize(850, 500)
        self.trace_path = tk.StringVar()
        self.status = tk.StringVar(value="Load a synthetic diagnostic trace.")
        self._build()

    def _build(self) -> None:
        toolbar = ttk.Frame(self, padding=10)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Open Trace", command=self._open).pack(side="left")
        ttk.Entry(toolbar, textvariable=self.trace_path).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(toolbar, text="Analyze", command=self._analyze).pack(side="left")

        columns = ("line", "module", "verdict", "category", "title", "detail", "payload")
        self.grid = ttk.Treeview(self, columns=columns, show="headings")
        headings = {
            "line": "Line",
            "module": "Module",
            "verdict": "Verdict",
            "category": "Category",
            "title": "Finding",
            "detail": "Detail",
            "payload": "Payload",
        }
        for key, text in headings.items():
            self.grid.heading(key, text=text)
        self.grid.column("line", width=55, anchor="center")
        self.grid.column("module", width=100)
        self.grid.column("verdict", width=75, anchor="center")
        self.grid.column("category", width=90)
        self.grid.column("title", width=210)
        self.grid.column("detail", width=350)
        self.grid.column("payload", width=170)
        self.grid.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        ttk.Label(self, textvariable=self.status, padding=8).pack(fill="x")

    def _open(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Text traces", "*.txt"), ("All files", "*.*")])
        if path:
            self.trace_path.set(path)

    def _analyze(self) -> None:
        path = self.trace_path.get().strip()
        if not path:
            messagebox.showwarning("Trace required", "Select a synthetic trace file first.")
            return
        try:
            events = load_trace(path)
            findings, states, metrics = analyze(events)
            output_dir = Path(path).parent / "reports"
            export_reports(output_dir, events, findings, states, metrics)
        except (FileNotFoundError, TraceFormatError, OSError) as exc:
            messagebox.showerror("Analysis error", str(exc))
            return

        for item in self.grid.get_children():
            self.grid.delete(item)
        for finding in findings:
            self.grid.insert(
                "",
                "end",
                values=(
                    finding.line_number,
                    finding.module,
                    finding.verdict,
                    finding.category,
                    finding.title,
                    finding.detail,
                    finding.payload_hex,
                ),
            )
        failures = sum(finding.verdict == "FAIL" for finding in findings)
        self.status.set(
            f"Analyzed {len(events)} events. Findings: {len(findings)}. Failures: {failures}. Reports: {output_dir}"
        )


def main() -> None:
    AnalyzerApp().mainloop()


if __name__ == "__main__":
    main()
