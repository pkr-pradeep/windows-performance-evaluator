from __future__ import annotations

import ctypes
import json
import os
import queue
import subprocess
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any


LARGE_FILE_BYTES = 100_000_000
LARGE_PROCESS_BYTES = 200_000_000
MEMORY_GROWTH_BYTES = 100_000_000
MEMORY_GROWTH_RATIO = 0.25
TEMPERATURE_LIMIT_C = 80.0
TEMPERATURE_RISE_C = 10.0
ANOMALY_WINDOW_SECONDS = 60.0
PROCESS_SAMPLE_INTERVAL_MS = 5_000
DRIVER_SAMPLE_INTERVAL_MS = 15_000
FILE_COLUMNS = ("checked", "name", "path", "size")
PROCESS_COLUMNS = ("checked", "name", "pid", "memory")
DRIVER_COLUMNS = ("status", "name", "instance", "version", "inf", "provider")


def file_matches_filters(
    path: Path, name_filter: str, extensions: set[str]
) -> bool:
    if name_filter and name_filter.casefold() not in path.name.casefold():
        return False
    if extensions and path.suffix.casefold() not in extensions:
        return False
    return True


def parse_extensions(value: str) -> set[str]:
    return {
        extension.casefold()
        if extension.startswith(".")
        else f".{extension.casefold()}"
        for extension in (part.strip() for part in value.split(","))
        if extension
    }


def format_size(size: int) -> str:
    return f"{size / 1_000_000:,.1f} MB"


def format_checked_rows(
    headings: tuple[str, ...], rows: list[tuple[str, ...]]
) -> str:
    return "\n".join(("\t".join(headings), *("\t".join(row) for row in rows)))


def driver_state_has_issue(records: list[dict[str, str]]) -> bool:
    if not records:
        return True
    for record in records:
        present = record.get("present", "").strip().casefold()
        problem = record.get("problem", "").strip().casefold()
        status = record.get("status", "").strip().casefold()
        if (
            present in {"false", "0"}
            or problem not in {"", "0", "none"}
            or status not in {"", "ok", "unknown"}
        ):
            return True
    return False


def format_driver_history_details(record: dict[str, Any]) -> str:
    lines = [str(record.get("details", ""))]
    if record.get("is_issue"):
        related_events = record.get("related_events", [])
        log_errors = record.get("log_errors", [])
        if not isinstance(related_events, list):
            related_events = []
        if not isinstance(log_errors, list):
            log_errors = [str(log_errors)]
        if related_events:
            lines.extend(("", "Related Windows System events:"))
            for event in related_events:
                if not isinstance(event, dict):
                    continue
                event_summary = (
                    f"{event.get('Time', 'Unknown time')} | "
                    f"{event.get('Log', 'System')} | "
                    f"{event.get('Provider', 'Unknown provider')} | "
                    f"Event ID {event.get('EventId', 'unknown')} | "
                    f"Record ID {event.get('RecordId', 'unknown')}"
                )
                lines.extend((event_summary, str(event.get("Message", ""))))
        elif log_errors:
            lines.extend(
                (
                    "",
                    "Windows System events could not be checked successfully.",
                )
            )
        else:
            lines.extend(
                (
                    "",
                    "No matching Windows System events were found in the "
                    "capture window. This does not confirm that no event occurred.",
                )
            )
        for error in log_errors:
            lines.append(f"Could not read Windows System log: {error}")
    return "\n".join(lines)


def memory_growth_anomaly(samples: list[tuple[float, int]]) -> bool:
    if len(samples) < 2:
        return False
    latest_time, latest_memory = samples[-1]
    recent = [
        sample
        for sample in samples
        if latest_time - sample[0] <= ANOMALY_WINDOW_SECONDS
    ]
    if len(recent) < 2:
        return False
    baseline_memory = recent[0][1]
    increase = latest_memory - baseline_memory
    return (
        baseline_memory > 0
        and increase >= MEMORY_GROWTH_BYTES
        and increase / baseline_memory >= MEMORY_GROWTH_RATIO
    )


def temperature_anomaly(samples: list[tuple[float, float]]) -> bool:
    if not samples:
        return False
    latest_time, latest_temperature = samples[-1]
    recent = [
        sample
        for sample in samples
        if latest_time - sample[0] <= ANOMALY_WINDOW_SECONDS
    ]
    return latest_temperature >= TEMPERATURE_LIMIT_C or (
        len(recent) >= 2
        and latest_temperature - recent[0][1] >= TEMPERATURE_RISE_C
    )


def file_size_without_following_symlinks(path: Path) -> int:
    return path.lstat().st_size


def is_directory_within_root(directory: str, root: str) -> bool:
    try:
        root_path = os.path.normcase(os.path.abspath(root))
        directory_path = os.path.normcase(os.path.abspath(directory))
        return os.path.commonpath((root_path, directory_path)) == root_path
    except (OSError, ValueError):
        return False


def child_directories(directory: str) -> list[str]:
    with os.scandir(directory) as entries:
        return sorted(
            (
                entry.path
                for entry in entries
                if entry.is_dir(follow_symlinks=False)
            ),
            key=str.casefold,
        )


def command_error_message(error: Exception) -> str:
    if isinstance(error, subprocess.CalledProcessError) and error.stderr:
        return error.stderr.strip()
    return str(error)


def available_drives() -> list[str]:
    if os.name != "nt":
        return []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    return [f"{chr(65 + index)}:\\" for index in range(26) if mask & (1 << index)]


def driver_history_file() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    return base / "WindowsPerformanceEvaluator" / "driver-history.jsonl"


class FileSearchTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook) -> None:
        super().__init__(parent, padding=10)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.cancel_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.worker: threading.Thread | None = None
        self.checked: set[str] = set()
        self.directory_root = ""
        self.directory_choices: dict[str, str | None] = {}
        self.progress_lock = threading.Lock()
        self.latest_progress = ""
        self._build_ui()
        self.after(100, self._process_events)

    def _build_ui(self) -> None:
        self.status = tk.StringVar(
            value="Select a drive and search. No files are changed."
        )
        filters = ttk.Frame(self)
        filters.pack(fill="x", pady=(0, 8))

        ttk.Label(filters, text="Drive").grid(row=0, column=0, sticky="w")
        drives = available_drives()
        self.drive = tk.StringVar(value=drives[0] if drives else "")
        self.drive_box = ttk.Combobox(
            filters, textvariable=self.drive, values=drives, width=8, state="readonly"
        )
        self.drive_box.grid(row=1, column=0, sticky="ew", padx=(0, 10))
        self.drive_box.bind("<<ComboboxSelected>>", self._drive_changed)

        ttk.Label(filters, text="Name contains").grid(row=0, column=1, sticky="w")
        self.name_filter = tk.StringVar()
        ttk.Entry(filters, textvariable=self.name_filter, width=24).grid(
            row=1, column=1, sticky="ew", padx=(0, 10)
        )

        ttk.Label(filters, text="Extensions (comma-separated)").grid(
            row=0, column=2, sticky="w"
        )
        self.extension_filter = tk.StringVar()
        ttk.Entry(filters, textvariable=self.extension_filter, width=26).grid(
            row=1, column=2, sticky="ew", padx=(0, 10)
        )
        filters.columnconfigure(1, weight=1)
        filters.columnconfigure(2, weight=1)

        ttk.Label(
            filters,
            text="Directory (optional; choose a folder from the dropdown)",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(8, 0))
        self.directory = tk.StringVar()
        self.directory_box = ttk.Combobox(
            filters, textvariable=self.directory, state="readonly"
        )
        self.directory_box.grid(
            row=3, column=0, columnspan=4, sticky="ew", pady=(0, 4)
        )
        self.directory_box.bind("<<ComboboxSelected>>", self._directory_changed)
        filters.columnconfigure(3, weight=0)
        if self.drive.get():
            self._reset_directory_choices()

        self.large_only = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            filters,
            text=f"Only files larger than {LARGE_FILE_BYTES // 1_000_000} MB",
            variable=self.large_only,
        ).grid(row=4, column=0, columnspan=4, sticky="w", pady=(8, 0))

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(0, 8))
        self.search_button = ttk.Button(actions, text="Search drive", command=self.search)
        self.search_button.pack(side="left")
        self.cancel_button = ttk.Button(
            actions, text="Cancel search", command=self.cancel, state="disabled"
        )
        self.cancel_button.pack(side="left", padx=6)
        self.pause_button = ttk.Button(
            actions, text="Pause search", command=self.toggle_pause, state="disabled"
        )
        self.pause_button.pack(side="left")
        ttk.Button(
            actions, text="Delete checked files…", command=self.delete_checked
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions, text="Copy checked", command=self.copy_checked
        ).pack(side="left", padx=(8, 0))

        self.tree = self._make_tree(
            FILE_COLUMNS, ("Select", "File name", "Full path", "Size")
        )
        self.tree.column("checked", width=55, anchor="center", stretch=False)
        self.tree.column("name", width=200)
        self.tree.column("path", width=520)
        self.tree.column("size", width=110, anchor="e", stretch=False)
        self.tree.bind("<Button-1>", self._toggle_file_checkbox)

        ttk.Label(self, textvariable=self.status).pack(fill="x", pady=(6, 0))

    def _drive_changed(self, _: tk.Event) -> None:
        self._reset_directory_choices()

    def _reset_directory_choices(self) -> None:
        root = self.drive.get()
        self.directory_root = os.path.abspath(root) if root else ""
        if not self.directory_root or not Path(self.directory_root).is_dir():
            self.directory_choices = {}
            self.directory_box.configure(values=())
            self.directory.set("")
            return
        self.directory_choices = {"All drive (root)": None}
        try:
            for path in child_directories(self.directory_root):
                self.directory_choices[path] = path
        except OSError as error:
            self.status.set(f"Could not list directories: {error}")
        self._show_directory_choices("All drive (root)")

    def _show_directory_choices(self, selected: str) -> None:
        values = list(self.directory_choices)
        self.directory_box.configure(values=values)
        self.directory.set(selected if selected in self.directory_choices else values[0])

    def _directory_changed(self, _: tk.Event) -> None:
        selected = self.directory.get()
        if selected not in self.directory_choices:
            return
        path = self.directory_choices[selected]
        if path is None:
            self._reset_directory_choices()
            return

        updated_choices: dict[str, str | None] = {
            f"Search this folder: {path}": path,
        }
        parent = os.path.dirname(path)
        if parent and os.path.normcase(parent) != os.path.normcase(path):
            parent_label = f"Up one level: {parent}"
            updated_choices[parent_label] = parent
        try:
            for child in child_directories(path):
                updated_choices[child] = child
        except OSError as error:
            self.status.set(f"Could not list directories in {path}: {error}")
        self.directory_choices = updated_choices
        self._show_directory_choices(f"Search this folder: {path}")

    def _make_tree(
        self, columns: tuple[str, ...], headings: tuple[str, ...]
    ) -> ttk.Treeview:
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        tree = ttk.Treeview(container, columns=columns, show="headings", selectmode="browse")
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading)
        vertical = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        return tree

    def search(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        root = self.drive.get()
        if not root or not Path(root).is_dir():
            messagebox.showerror("Drive unavailable", "Select an available drive.")
            return
        selected_directory = self.directory_choices.get(self.directory.get())
        if selected_directory is not None:
            if not Path(selected_directory).is_dir():
                messagebox.showerror("Directory unavailable", "Choose an existing directory.")
                return
            if not is_directory_within_root(selected_directory, root):
                messagebox.showerror(
                    "Directory is outside the selected drive",
                    f"Choose a directory located on {root}.",
                )
                return
            root = selected_directory

        self.checked.clear()
        self.tree.delete(*self.tree.get_children())
        self.cancel_event.clear()
        self.pause_event.set()
        name_filter = self.name_filter.get().strip()
        extensions = parse_extensions(self.extension_filter.get())
        large_only = self.large_only.get()
        self.search_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.pause_button.configure(state="normal", text="Pause search")
        self.status.set(f"Starting search in {root}…")
        self.worker = threading.Thread(
            target=self._scan,
            args=(root, name_filter, extensions, large_only),
            daemon=True,
        )
        self.worker.start()

    def _scan(
        self, root: str, name_filter: str, extensions: set[str], large_only: bool
    ) -> None:
        found = 0
        inaccessible = 0
        batch: list[tuple[str, str, str, str]] = []

        def on_walk_error(_: OSError) -> None:
            nonlocal inaccessible
            inaccessible += 1

        for directory, subdirectories, filenames in os.walk(
            root, onerror=on_walk_error, followlinks=False
        ):
            if not self._wait_until_resumed():
                break
            if self.cancel_event.is_set():
                break
            self._set_progress(f"Scanning directory: {directory}")
            directory_found = 0
            subdirectories[:] = [
                name
                for name in subdirectories
                if not os.path.islink(os.path.join(directory, name))
            ]
            for filename in filenames:
                if not self._wait_until_resumed():
                    break
                if self.cancel_event.is_set():
                    break
                path = Path(directory, filename)
                if not file_matches_filters(path, name_filter, extensions):
                    continue
                try:
                    size = file_size_without_following_symlinks(path)
                except OSError:
                    inaccessible += 1
                    continue
                if large_only and size <= LARGE_FILE_BYTES:
                    continue
                batch.append((str(path), filename, str(path), format_size(size)))
                found += 1
                directory_found += 1
                if directory_found == 1 or len(batch) >= 25:
                    self.events.put(("files", batch))
                    batch = []
                    if directory_found == 1:
                        self._set_progress(
                            f"Found first matching file in {directory}: {filename}"
                        )
            if batch:
                self.events.put(("files", batch))
                batch = []
            if not self.cancel_event.is_set():
                result = (
                    f"{directory_found} matching file(s)"
                    if directory_found
                    else "no matching files"
                )
                self._set_progress(
                    f"Directory complete: {directory} — {result}"
                )
        if batch:
            self.events.put(("files", batch))
        self.events.put(("finished", (found, inaccessible, self.cancel_event.is_set())))

    def _wait_until_resumed(self) -> bool:
        while not self.cancel_event.is_set():
            if self.pause_event.wait(timeout=0.1):
                return True
        return False

    def _set_progress(self, message: str) -> None:
        with self.progress_lock:
            self.latest_progress = message

    def _process_events(self) -> None:
        with self.progress_lock:
            progress = self.latest_progress
            self.latest_progress = ""
        if progress and self.pause_event.is_set():
            self.status.set(progress)
        for _ in range(100):
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "files":
                for values in payload:
                    self.tree.insert("", "end", iid=values[0], values=("☐", *values[1:]))
            else:
                found, inaccessible, cancelled = payload
                self.search_button.configure(state="normal")
                self.cancel_button.configure(state="disabled")
                self.pause_button.configure(state="disabled", text="Pause search")
                result = f"Found {found:,} matching file(s)."
                if inaccessible:
                    result += f" Skipped {inaccessible:,} inaccessible item(s)."
                if cancelled:
                    result += " Search cancelled."
                self.status.set(result)
        self.after(50, self._process_events)

    def _toggle_file_checkbox(self, event: tk.Event) -> None:
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        if self.tree.identify_column(event.x) != "#1":
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        if item in self.checked:
            self.checked.remove(item)
            symbol = "☐"
        else:
            self.checked.add(item)
            symbol = "☑"
        self.tree.set(item, "checked", symbol)

    def cancel(self) -> None:
        self.cancel_event.set()
        self.pause_event.set()
        self.status.set("Cancelling search…")

    def copy_checked(self) -> None:
        rows = [
            tuple(self.tree.set(item, column) for column in ("name", "path", "size"))
            for item in self.tree.get_children("")
            if item in self.checked
        ]
        if not rows:
            messagebox.showinfo("No files selected", "Check one or more files first.")
            return
        self._copy_rows(("File name", "Full path", "Size"), rows)

    def _copy_rows(
        self, headings: tuple[str, ...], rows: list[tuple[str, ...]]
    ) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(format_checked_rows(headings, rows))
            self.update_idletasks()
        except tk.TclError as error:
            messagebox.showerror("Copy failed", f"Could not copy selected rows: {error}")
            return
        self.status.set(f"Copied {len(rows):,} checked row(s) to the clipboard.")

    def toggle_pause(self) -> None:
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.pause_button.configure(text="Resume search")
            self.status.set("Search paused.")
        else:
            self.pause_event.set()
            self.pause_button.configure(text="Pause search")
            self.status.set("Resuming search…")

    def delete_checked(self) -> None:
        paths = [path for path in self.checked if os.path.isfile(path)]
        if not paths:
            messagebox.showinfo("No files selected", "Check one or more files first.")
            return
        preview = "\n".join(paths[:5])
        if len(paths) > 5:
            preview += f"\n…and {len(paths) - 5} more"
        confirmed = messagebox.askyesno(
            "Confirm permanent deletion",
            f"Permanently delete {len(paths)} selected file(s)?\n\n"
            f"{preview}\n\nThis cannot be undone.",
            icon="warning",
        )
        if not confirmed:
            return

        deleted = 0
        errors: list[str] = []
        for path in paths:
            try:
                os.remove(path)
                self.tree.delete(path)
                self.checked.discard(path)
                deleted += 1
            except OSError as error:
                errors.append(f"{path}: {error}")
        summary = f"Deleted {deleted} file(s)."
        if errors:
            summary += "\n\nCould not delete:\n" + "\n".join(errors[:10])
            if len(errors) > 10:
                summary += f"\n…and {len(errors) - 10} more error(s)"
            messagebox.showwarning("Deletion incomplete", summary)
        else:
            messagebox.showinfo("Deletion complete", summary)
        self.status.set(summary.split("\n", 1)[0])


class ProcessTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook) -> None:
        super().__init__(parent, padding=10)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.checked: set[str] = set()
        self.samples: dict[str, tuple[str, list[tuple[float, int]]]] = {}
        self.temperature_samples: list[tuple[float, float]] = []
        self.sample_running = False
        self.temperature_alert = False
        self._build_ui()
        self.after(100, self._process_events)
        self.after(300, self._begin_sample)
        self.after(PROCESS_SAMPLE_INTERVAL_MS, self._schedule_sample)

    def _build_ui(self) -> None:
        filters = ttk.Frame(self)
        filters.pack(fill="x", pady=(0, 8))
        ttk.Label(filters, text="Process name contains").pack(side="left")
        self.name_filter = tk.StringVar()
        ttk.Entry(filters, textvariable=self.name_filter, width=28).pack(
            side="left", padx=8
        )
        self.large_only = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            filters,
            text="Only processes using more than 200 MB",
            variable=self.large_only,
        ).pack(side="left", padx=8)

        self.temperature_label = ttk.Label(
            self,
            text="System temperature: waiting for sensor data…",
            padding=(6, 4),
        )
        self.temperature_label.pack(fill="x", pady=(0, 8))
        style = ttk.Style(self)
        style.configure("ProcessTemp.Alert.TLabel", foreground="#8b0000")

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Sample now", command=self._begin_sample).pack(
            side="left"
        )
        ttk.Button(
            actions, text="End checked processes…", command=self.end_checked
        ).pack(side="left", padx=8)
        ttk.Button(
            actions, text="Copy checked", command=self.copy_checked
        ).pack(side="left")

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(
            container, columns=PROCESS_COLUMNS, show="headings", selectmode="browse"
        )
        for column, heading in zip(
            PROCESS_COLUMNS, ("Select", "Process", "PID", "Memory")
        ):
            self.tree.heading(column, text=heading)
        self.tree.column("checked", width=55, anchor="center", stretch=False)
        self.tree.column("name", width=300)
        self.tree.column("pid", width=100, anchor="e", stretch=False)
        self.tree.column("memory", width=130, anchor="e", stretch=False)
        self.tree.tag_configure("memory_alert", background="#ffd6d6", foreground="#8b0000")
        vertical = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vertical.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        self.tree.bind("<Button-1>", self._toggle_process_checkbox)
        self.status = tk.StringVar(value="Processes are listed for review only.")
        ttk.Label(self, textvariable=self.status).pack(fill="x", pady=(6, 0))

    def _schedule_sample(self) -> None:
        self._begin_sample()
        self.after(PROCESS_SAMPLE_INTERVAL_MS, self._schedule_sample)

    def _begin_sample(self) -> None:
        if self.sample_running:
            return
        self.sample_running = True
        self.status.set("Sampling processes and available temperature sensors…")
        threading.Thread(target=self._load_sample, daemon=True).start()

    def _load_sample(self) -> None:
        script = (
            "$processes = @(Get-Process | "
            "Select-Object Id,ProcessName,WorkingSet64); "
            "$temperatures = @(Get-CimInstance -Namespace root/wmi "
            "-ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | "
            "ForEach-Object { [math]::Round(($_.CurrentTemperature / 10) - 273.15, 1) }); "
            "[pscustomobject]@{ Processes = $processes; "
            "Temperatures = $temperatures } | ConvertTo-Json -Depth 3 -Compress"
        )
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                timeout=30,
            )
            data = json.loads(completed.stdout)
            process_data = data["Processes"]
            if isinstance(process_data, dict):
                process_data = [process_data]
            temperatures = data["Temperatures"]
            if isinstance(temperatures, (int, float)):
                temperatures = [temperatures]
            processes = [
                (str(item["Id"]), str(item["ProcessName"]), int(item["WorkingSet64"]))
                for item in process_data
            ]
            self.events.put(("sample", (time.monotonic(), processes, temperatures)))
        except (
            OSError,
            subprocess.SubprocessError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            self.events.put(("error", command_error_message(error)))
        finally:
            self.events.put(("sample_done", None))

    def _process_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "error":
                    self.status.set(f"Could not load processes: {payload}")
                elif event == "sample":
                    self._apply_sample(*payload)
                else:
                    self.sample_running = False
        except queue.Empty:
            pass
        self.after(100, self._process_events)

    def _apply_sample(
        self,
        sampled_at: float,
        processes: list[tuple[str, str, int]],
        temperatures: list[float],
    ) -> None:
        current_pids: set[str] = set()
        alerts: dict[str, bool] = {}
        for pid, name, memory in processes:
            current_pids.add(pid)
            previous = self.samples.get(pid)
            history = previous[1] if previous and previous[0] == name else []
            history.append((sampled_at, memory))
            history[:] = [
                sample
                for sample in history
                if sampled_at - sample[0] <= ANOMALY_WINDOW_SECONDS
            ]
            self.samples[pid] = (name, history)
            alerts[pid] = memory_growth_anomaly(history)
        self.samples = {
            pid: history
            for pid, history in self.samples.items()
            if pid in current_pids
        }

        if temperatures:
            temperature = max(float(value) for value in temperatures)
            self.temperature_samples.append((sampled_at, temperature))
            self.temperature_samples = [
                sample
                for sample in self.temperature_samples
                if sampled_at - sample[0] <= ANOMALY_WINDOW_SECONDS
            ]
            self.temperature_alert = temperature_anomaly(self.temperature_samples)
            if self.temperature_alert:
                reason = "high" if temperature >= TEMPERATURE_LIMIT_C else "rapidly rising"
                self.temperature_label.configure(
                    text=(
                        f"System temperature: {temperature:.1f}°C — {reason} "
                        f"(alert at {TEMPERATURE_LIMIT_C:.0f}°C or a "
                        f"{TEMPERATURE_RISE_C:.0f}°C rise in 60 sec)"
                    ),
                    style="ProcessTemp.Alert.TLabel",
                )
            else:
                self.temperature_label.configure(
                    text=f"System temperature: {temperature:.1f}°C",
                    style="TLabel",
                )
        else:
            self.temperature_alert = False
            self.temperature_samples.clear()
            self.temperature_label.configure(
                text=(
                    "System temperature unavailable: Windows did not report an "
                    "ACPI thermal-zone sensor."
                ),
                style="TLabel",
            )

        self.checked.intersection_update(current_pids)
        self.tree.delete(*self.tree.get_children())
        name_filter = self.name_filter.get().strip().casefold()
        large_only = self.large_only.get()
        shown = 0
        alert_count = sum(alerts.values())
        for pid, name, memory in processes:
            if name_filter and name_filter not in name.casefold():
                continue
            is_alert = alerts.get(pid, False)
            if large_only and memory <= LARGE_PROCESS_BYTES and not is_alert:
                continue
            self.tree.insert(
                "",
                "end",
                iid=pid,
                values=(
                    "☑" if pid in self.checked else "☐",
                    name,
                    pid,
                    format_size(memory),
                ),
                tags=("memory_alert",) if is_alert else (),
            )
            shown += 1
        status = (
            f"Monitoring every {PROCESS_SAMPLE_INTERVAL_MS // 1000} sec. "
            f"Showing {shown:,} process(es); {alert_count:,} memory alert(s)."
        )
        if self.temperature_alert:
            status += " System temperature alert."
        self.status.set(status)

    def _toggle_process_checkbox(self, event: tk.Event) -> None:
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        if self.tree.identify_column(event.x) != "#1":
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        if item in self.checked:
            self.checked.remove(item)
            symbol = "☐"
        else:
            self.checked.add(item)
            symbol = "☑"
        self.tree.set(item, "checked", symbol)

    def copy_checked(self) -> None:
        rows = [
            tuple(
                self.tree.set(item, column)
                for column in ("name", "pid", "memory")
            )
            for item in self.tree.get_children("")
            if item in self.checked
        ]
        if not rows:
            messagebox.showinfo(
                "No processes selected", "Check one or more processes first."
            )
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(
                format_checked_rows(("Process", "PID", "Memory"), rows)
            )
            self.update_idletasks()
        except tk.TclError as error:
            messagebox.showerror("Copy failed", f"Could not copy selected rows: {error}")
            return
        self.status.set(f"Copied {len(rows):,} checked row(s) to the clipboard.")

    def end_checked(self) -> None:
        processes = [
            (pid, self.tree.set(pid, "name"))
            for pid in self.checked
            if self.tree.exists(pid)
        ]
        if not processes:
            messagebox.showinfo(
                "No processes selected", "Check one or more processes first."
            )
            return
        preview = "\n".join(f"{name} (PID {pid})" for pid, name in processes[:10])
        if len(processes) > 10:
            preview += f"\n…and {len(processes) - 10} more"
        if not messagebox.askyesno(
            "Confirm process termination",
            f"Force-end {len(processes)} selected process(es)?\n\n"
            f"{preview}\n\nUnsaved work in these processes may be lost.",
            icon="warning",
        ):
            return

        ended = 0
        errors: list[str] = []
        for pid, name in processes:
            try:
                subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        f"Stop-Process -Id {int(pid)} -Force -ErrorAction Stop",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    timeout=15,
                )
                if self.tree.exists(pid):
                    self.tree.delete(pid)
                self.checked.discard(pid)
                ended += 1
            except (OSError, subprocess.SubprocessError, ValueError) as error:
                errors.append(
                    f"{name} (PID {pid}): {command_error_message(error)}"
                )

        summary = f"Ended {ended} process(es)."
        if errors:
            summary += "\n\nCould not end:\n" + "\n".join(errors[:10])
            if len(errors) > 10:
                summary += f"\n…and {len(errors) - 10} more error(s)"
            messagebox.showwarning("Some processes could not be ended", summary)
        else:
            messagebox.showinfo("Process termination complete", summary)
        self.status.set(summary.split("\n", 1)[0])


class DriverMonitorTab(ttk.Frame):
    DEFAULT_DEVICE_NAME = "Realtek 8852BE Wireless LAN WiFi 6 PCI-E NIC"

    def __init__(self, parent: ttk.Notebook) -> None:
        super().__init__(parent, padding=10)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.monitoring = True
        self.poll_running = False
        self.last_signature: tuple[tuple[str, ...], ...] | None = None
        self.seen_event_keys: set[str] = set()
        self.checked_history: set[str] = set()
        self.known_device_ids: set[str] = set()
        self.history_records: dict[str, dict[str, Any]] = {}
        self.history_path = driver_history_file()
        self.persistence_error = ""
        self._build_ui()
        self._load_history()
        self.after(100, self._process_events)
        self.after(300, self._begin_poll)
        self.after(DRIVER_SAMPLE_INTERVAL_MS, self._schedule_poll)

    def _build_ui(self) -> None:
        controls = ttk.Frame(self)
        controls.pack(fill="x", pady=(0, 8))
        ttk.Label(controls, text="Device Manager name contains").grid(
            row=0, column=0, sticky="w"
        )
        self.device_name = tk.StringVar(value=self.DEFAULT_DEVICE_NAME)
        ttk.Entry(controls, textvariable=self.device_name).grid(
            row=1, column=0, sticky="ew", padx=(0, 8)
        )
        ttk.Button(controls, text="Check now", command=self._begin_poll).grid(
            row=1, column=1, padx=(0, 8)
        )
        self.monitor_button = ttk.Button(
            controls, text="Stop monitoring", command=self._toggle_monitoring
        )
        self.monitor_button.grid(row=1, column=2)
        ttk.Button(
            controls, text="Copy checked", command=self.copy_checked_history
        ).grid(row=1, column=3, padx=(8, 0))
        controls.columnconfigure(0, weight=1)

        self.status = tk.StringVar(value="Starting device monitoring…")
        ttk.Label(self, textvariable=self.status).pack(fill="x", pady=(0, 6))
        ttk.Label(self, text="Matching devices and signed driver packages").pack(
            anchor="w"
        )
        self.devices = ttk.Treeview(
            self, columns=DRIVER_COLUMNS, show="headings", height=4
        )
        headings = (
            "Device status",
            "Device",
            "Device instance ID",
            "Driver version",
            "INF",
            "Provider",
        )
        for column, heading in zip(DRIVER_COLUMNS, headings):
            self.devices.heading(column, text=heading)
        self.devices.column("status", width=120, stretch=False)
        self.devices.column("name", width=250)
        self.devices.column("instance", width=330)
        self.devices.column("version", width=100, stretch=False)
        self.devices.column("inf", width=100, stretch=False)
        self.devices.column("provider", width=180)
        self.devices.pack(fill="x", pady=(2, 8))

        ttk.Label(
            self,
            text=f"Activity history (also saved to {self.history_path})",
        ).pack(anchor="w")
        history_frame = ttk.Frame(self)
        history_frame.pack(fill="both", expand=True, pady=(2, 0))
        self.history = ttk.Treeview(
            history_frame,
            columns=("checked", "time", "kind", "details"),
            show="headings",
        )
        for column, heading in (
            ("checked", "Select"),
            ("time", "Time"),
            ("kind", "Event"),
            ("details", "Details"),
        ):
            self.history.heading(column, text=heading)
        self.history.column("checked", width=55, anchor="center", stretch=False)
        self.history.column("time", width=165, stretch=False)
        self.history.column("kind", width=190, stretch=False)
        self.history.column("details", width=550)
        self.history.bind("<Button-1>", self._toggle_history_checkbox)
        self.history.bind("<<TreeviewSelect>>", self._show_history_details)
        scrollbar = ttk.Scrollbar(
            history_frame, orient="vertical", command=self.history.yview
        )
        self.history.configure(yscrollcommand=scrollbar.set)
        self.history.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        history_frame.rowconfigure(0, weight=1)
        history_frame.columnconfigure(0, weight=1)

        ttk.Label(self, text="Selected entry details").pack(anchor="w", pady=(6, 0))
        details_frame = ttk.Frame(self)
        details_frame.pack(fill="x", pady=(2, 0))
        self.history_details = tk.Text(
            details_frame, height=6, wrap="word", state="disabled"
        )
        details_scrollbar = ttk.Scrollbar(
            details_frame, orient="vertical", command=self.history_details.yview
        )
        self.history_details.configure(yscrollcommand=details_scrollbar.set)
        self.history_details.pack(side="left", fill="both", expand=True)
        details_scrollbar.pack(side="right", fill="y")

    def _toggle_monitoring(self) -> None:
        self.monitoring = not self.monitoring
        self.monitor_button.configure(
            text="Stop monitoring" if self.monitoring else "Start monitoring"
        )
        if self.monitoring:
            self._begin_poll()
        else:
            self.status.set("Monitoring paused. Use Check now for a one-time scan.")

    def _schedule_poll(self) -> None:
        if self.monitoring:
            self._begin_poll()
        self.after(DRIVER_SAMPLE_INTERVAL_MS, self._schedule_poll)

    def _begin_poll(self) -> None:
        if self.poll_running:
            return
        name = self.device_name.get().strip()
        if not name:
            self.status.set("Enter a device name to monitor.")
            return
        self.poll_running = True
        self.status.set("Checking Plug and Play state, driver details, and Windows events…")
        threading.Thread(target=self._poll, args=(name,), daemon=True).start()

    def _poll(self, name: str) -> None:
        script = r"""
$needle = $env:WPE_DEVICE_NAME
$devices = @(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -like "*$needle*" -or $_.InstanceId -like "*$needle*" })
$drivers = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
    Where-Object { $_.DeviceName -like "*$needle*" -or $_.DeviceID -like "*$needle*" })
$records = @()
$matchedIds = @()
foreach ($device in $devices) {
    $matchedIds += $device.InstanceId
    $driver = $drivers | Where-Object { $_.DeviceID -eq $device.InstanceId } | Select-Object -First 1
    $records += [pscustomobject]@{
        Status = [string]$device.Status
        Present = $device.Present
        Problem = $device.Problem
        Name = [string]$device.FriendlyName
        Instance = [string]$device.InstanceId
        Version = [string]$driver.DriverVersion
        Inf = [string]$driver.InfName
        Provider = [string]$driver.DriverProviderName
        DriverDate = [string]$driver.DriverDate
        Service = [string]$driver.Service
    }
}
foreach ($driver in $drivers) {
    if ($matchedIds -notcontains $driver.DeviceID) {
        $records += [pscustomobject]@{
            Status = 'Driver package only'
            Present = $false
            Problem = $null
            Name = [string]$driver.DeviceName
            Instance = [string]$driver.DeviceID
            Version = [string]$driver.DriverVersion
            Inf = [string]$driver.InfName
            Provider = [string]$driver.DriverProviderName
            DriverDate = [string]$driver.DriverDate
            Service = [string]$driver.Service
        }
    }
}
$knownIds = @()
if ($env:WPE_DEVICE_INSTANCE_IDS) {
    $knownIds = @($env:WPE_DEVICE_INSTANCE_IDS | ConvertFrom-Json)
}
$events = @()
$logErrors = @()
try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        StartTime = (Get-Date).AddMinutes(-10)
    } -MaxEvents 250 -ErrorAction Stop |
        Where-Object {
            $eventMessage = [string]$_.Message
            $eventXml = [string]$_.ToXml()
            $eventText = "$eventMessage $eventXml"
            $deviceMatch = $eventText -like "*$needle*"
            foreach ($instance in @($matchedIds) + @($knownIds)) {
                if ($instance -and $eventText -like "*$instance*") {
                    $deviceMatch = $true
                    break
                }
            }
            $deviceMatch
        } |
        Select-Object -First 20 |
        ForEach-Object {
            $message = [string]$_.Message
            if ($message.Length -gt 3000) {
                $message = $message.Substring(0, 3000)
            }
            [pscustomobject]@{
                RecordId = [string]$_.RecordId
                Time = $_.TimeCreated.ToString('o')
                Log = 'System'
                Provider = [string]$_.ProviderName
                EventId = [int]$_.Id
                Message = $message
            }
        })
} catch {
    if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
        $logErrors += [string]$_.Exception.Message
    }
}
[pscustomobject]@{ Devices = @($records); Events = @($events); LogErrors = @($logErrors) } |
    ConvertTo-Json -Depth 4 -Compress
"""
        environment = os.environ.copy()
        environment["WPE_DEVICE_NAME"] = name
        environment["WPE_DEVICE_INSTANCE_IDS"] = json.dumps(
            sorted(self.known_device_ids)
        )
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                timeout=45,
                env=environment,
            )
            result = json.loads(completed.stdout)
            devices = result.get("Devices", [])
            events = result.get("Events", [])
            log_errors = result.get("LogErrors", [])
            if devices is None:
                devices = []
            if events is None:
                events = []
            if log_errors is None:
                log_errors = []
            if isinstance(devices, dict):
                devices = [devices]
            if isinstance(events, dict):
                events = [events]
            if isinstance(log_errors, str):
                log_errors = [log_errors]
            self.events.put(("poll_result", (devices, events, log_errors)))
        except (
            OSError,
            subprocess.SubprocessError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as error:
            self.events.put(("poll_error", command_error_message(error)))
        finally:
            self.events.put(("poll_done", None))

    def _process_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "poll_result":
                    self._apply_poll_result(*payload)
                elif event == "poll_error":
                    self.status.set(f"Could not inspect driver/device state: {payload}")
                else:
                    self.poll_running = False
        except queue.Empty:
            pass
        self.after(100, self._process_events)

    def _apply_poll_result(
        self,
        devices: list[dict[str, Any]],
        windows_events: list[dict[str, Any]],
        log_errors: list[str],
    ) -> None:
        self.devices.delete(*self.devices.get_children())
        normalized: list[dict[str, str]] = []
        for device in devices:
            record = {
                key: "" if device.get(source) is None else str(device.get(source))
                for key, source in (
                    ("status", "Status"),
                    ("present", "Present"),
                    ("problem", "Problem"),
                    ("name", "Name"),
                    ("instance", "Instance"),
                    ("version", "Version"),
                    ("inf", "Inf"),
                    ("provider", "Provider"),
                    ("date", "DriverDate"),
                    ("service", "Service"),
                )
            }
            normalized.append(record)
            if record["instance"]:
                self.known_device_ids.add(record["instance"])
            self.devices.insert(
                "",
                "end",
                values=(
                    record["status"],
                    record["name"],
                    record["instance"],
                    record["version"],
                    record["inf"],
                    record["provider"],
                ),
            )
        if not normalized:
            self.devices.insert(
                "",
                "end",
                values=("Not found", self.device_name.get(), "", "", "", ""),
            )

        signature = tuple(
            sorted(
                (
                    self.device_name.get().strip().casefold(),
                    item["status"],
                    item["present"],
                    item["problem"],
                    item["name"],
                    item["instance"],
                    item["version"],
                    item["inf"],
                    item["provider"],
                    item["date"],
                    item["service"],
                )
                for item in normalized
            )
        )
        if signature != self.last_signature:
            is_issue = driver_state_has_issue(normalized)
            related_events = windows_events if is_issue else []
            detail = (
                "; ".join(
                    f"{item['name']}: status={item['status']}, "
                    f"present={item['present'] or 'unknown'}, "
                    f"problem={item['problem'] or 'none'}, "
                    f"version={item['version'] or 'unknown'}, "
                    f"INF={item['inf'] or 'unknown'}, "
                    f"provider={item['provider'] or 'unknown'}, "
                    f"date={item['date'] or 'unknown'}, "
                    f"service={item['service'] or 'unknown'}, "
                    f"instance={item['instance'] or 'unknown'}"
                    for item in normalized
                )
                if normalized
                else f"No matching PnP device or signed driver package for "
                f"{self.device_name.get()}."
            )
            if is_issue:
                detail += (
                    f" Related System logs: {len(related_events)} event(s) "
                    f"captured in the last 10 minutes."
                )
            self._record_history(
                "Device/driver state changed"
                if self.last_signature is not None
                else "Initial device/driver state",
                detail,
                is_issue=is_issue,
                related_events=related_events,
                log_errors=log_errors if is_issue else [],
                instance_ids=sorted(self.known_device_ids),
            )
            self.last_signature = signature

        for item in windows_events:
            record_id = str(item.get("RecordId", ""))
            key = f"System:{record_id}"
            if not record_id or key in self.seen_event_keys:
                continue
            self.seen_event_keys.add(key)
            self._record_history(
                f"Windows event {item.get('EventId', '')} "
                f"({item.get('Provider', 'PnP')})",
                str(item.get("Message", "")),
                timestamp=str(item.get("Time", "")),
                event_key=key,
            )

        state = (
            f"{len(normalized)} matching device/driver record(s); "
            f"checked {datetime.now().astimezone().strftime('%H:%M:%S')}."
        )
        if not normalized:
            state = "Device or signed driver package not found in current PnP inventory."
        if self.persistence_error:
            state += f" History file error: {self.persistence_error}"
        if self.monitoring:
            state += f" Monitoring every {DRIVER_SAMPLE_INTERVAL_MS // 1000} sec."
        self.status.set(state)

    def _load_history(self) -> None:
        try:
            lines = self.history_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return
        except OSError as error:
            self.persistence_error = str(error)
            return
        for line in lines[-500:]:
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                self.persistence_error = f"history contains invalid JSON: {error}"
                continue
            if not isinstance(record, dict):
                continue
            self._add_history_row(record)
            instance_ids = record.get("instance_ids", [])
            if isinstance(instance_ids, list):
                self.known_device_ids.update(
                    item for item in instance_ids if isinstance(item, str)
                )
            event_key = record.get("event_key")
            if isinstance(event_key, str):
                self.seen_event_keys.add(event_key)

    def _record_history(
        self,
        kind: str,
        details: str,
        timestamp: str | None = None,
        event_key: str | None = None,
        is_issue: bool = False,
        related_events: list[dict[str, Any]] | None = None,
        log_errors: list[str] | None = None,
        instance_ids: list[str] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "timestamp": timestamp or datetime.now().astimezone().isoformat(
                timespec="seconds"
            ),
            "kind": kind,
            "details": details,
        }
        if is_issue:
            record["is_issue"] = True
            record["related_events"] = related_events or []
            record["log_errors"] = log_errors or []
            record["instance_ids"] = instance_ids or []
        if event_key:
            record["event_key"] = event_key
        self._add_history_row(record)
        try:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            with self.history_path.open("a", encoding="utf-8") as history_file:
                history_file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.persistence_error = ""
        except OSError as error:
            self.persistence_error = str(error)

    def _toggle_history_checkbox(self, event: tk.Event) -> None:
        if self.history.identify("region", event.x, event.y) != "cell":
            return
        if self.history.identify_column(event.x) != "#1":
            return
        item = self.history.identify_row(event.y)
        if not item:
            return
        if item in self.checked_history:
            self.checked_history.remove(item)
            symbol = "☐"
        else:
            self.checked_history.add(item)
            symbol = "☑"
        self.history.set(item, "checked", symbol)

    def copy_checked_history(self) -> None:
        rows = [
            (
                self.history.set(item, "time"),
                self.history.set(item, "kind"),
                format_driver_history_details(self.history_records[item]),
            )
            for item in self.history.get_children("")
            if item in self.checked_history and item in self.history_records
        ]
        if not rows:
            messagebox.showinfo(
                "No history selected",
                "Check one or more Wi-Fi activity rows first.",
            )
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(
                format_checked_rows(("Time", "Event", "Details"), rows)
            )
            self.update_idletasks()
        except tk.TclError as error:
            messagebox.showerror("Copy failed", f"Could not copy selected rows: {error}")
            return
        self.status.set(f"Copied {len(rows):,} checked Wi-Fi row(s) to the clipboard.")

    def _show_history_details(self, event: tk.Event) -> None:
        if event.widget is not self.history:
            return
        selected = self.history.selection()
        text = (
            format_driver_history_details(self.history_records[selected[0]])
            if selected and selected[0] in self.history_records
            else ""
        )
        self.history_details.configure(state="normal")
        self.history_details.delete("1.0", "end")
        self.history_details.insert("1.0", text)
        self.history_details.configure(state="disabled")

    def _add_history_row(self, record: dict[str, Any]) -> None:
        timestamp = str(record.get("timestamp", ""))
        if "T" in timestamp:
            timestamp = timestamp.replace("T", " ", 1)
        row_details = str(record.get("details", ""))
        if record.get("is_issue"):
            event_count = len(record.get("related_events", []))
            row_details += f" [{event_count} related System log(s)]"
        item = self.history.insert(
            "",
            "end",
            values=(
                "☐",
                timestamp,
                str(record.get("kind", "")),
                row_details,
            ),
        )
        self.history_records[item] = record
        children = self.history.get_children()
        if len(children) > 500:
            removed = children[: len(children) - 500]
            self.history.delete(*removed)
            self.checked_history.difference_update(removed)
            for removed_item in removed:
                self.history_records.pop(removed_item, None)


class FileProcessManager(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Windows File & Process Manager")
        self.geometry("1150x750")
        self.minsize(900, 600)
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        notebook.add(FileSearchTab(notebook), text="Large files")
        notebook.add(ProcessTab(notebook), text="Large processes")
        notebook.add(DriverMonitorTab(notebook), text="Wi-Fi driver")


if __name__ == "__main__":
    if os.name != "nt":
        raise SystemExit("This application is designed for Windows.")
    FileProcessManager().mainloop()
