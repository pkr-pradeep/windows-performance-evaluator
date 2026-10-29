# Windows File & Process Manager

A small Windows desktop utility for finding large files, monitoring a Plug and Play
device/driver, and reviewing process memory. It uses Python's built-in Tkinter UI and
has no third-party dependencies.

## Run

Install Python 3 with Tcl/Tk enabled, then run:

```powershell
python app.py
```

## Use

- **Large files:** choose a drive, then choose a folder from the directory
  dropdown or leave **All drive (root)** selected to search from the drive root.
  The dropdown lists the current folder's immediate subdirectories; choose a
  folder to move into it, and use **Up one level** to move back. Searches include
  the selected folder and its subfolders. Optionally filter by a case-insensitive
  name fragment and comma-separated extensions. Files larger than 100 MB are
  shown by default; uncheck the size filter to show all matching files.
- **Large processes:** processes are sampled every 5 seconds. A process row is
  highlighted when its working set grows by at least 100 MB and 25% within 60
  seconds. Alerting processes remain visible even when the 200 MB display filter
  is enabled. System temperature is reported separately because Windows does not
  attribute hardware temperature to an individual process. A temperature alert is
  shown at 80°C or after a 10°C rise within 60 seconds. Temperature readings depend
  on Windows exposing an ACPI thermal-zone sensor; otherwise the app reports that
  temperature is unavailable.
- **Wi-Fi driver:** the tab starts monitoring the configured Device Manager name
  every 15 seconds (default: Realtek 8852BE Wireless LAN WiFi 6 PCI-E NIC). It
  displays matching PnP devices and signed-driver metadata, including device
  presence/status, problem code, instance ID, version, INF, provider, date, and
  service. Changes to the observed state and matching PnP events from the Windows
  System event log are added to the activity history, which is also saved to
  `%LOCALAPPDATA%\WindowsPerformanceEvaluator\driver-history.jsonl`. Monitoring
  records changes only while the app is running; it cannot reconstruct earlier
  activity. When a device issue is detected, the app also attaches up to 20
  matching System events from the previous 10 minutes to that history entry.
  Select a history entry to inspect its full details; copying a checked issue row
  includes the attached event messages. Matching uses the configured device name
  and known device instance IDs. Windows may not record the cause, and events that
  cannot be matched or read may not be attached; any event-log read errors are
  shown with the issue details.
- Click the checkbox column to mark one or more rows. Listing and marking rows do
  not change files or processes. Use **Copy checked** on any tab to copy the
  checked rows as tab-separated text. On the Wi-Fi driver tab, check activity
  history rows to copy them.
- File deletion and forced process termination each require a separate confirmation.
  File deletion is permanent. Ending a process may discard unsaved work, and
  Windows may deny termination when the current user lacks permission.

Searches run in the background and can be cancelled. Matching files appear as
they are found; the status line reports the directory being scanned and whether
it had matches when scanning finishes. Use **Pause search** and **Resume search**
to temporarily stop or continue the scan. Inaccessible file-system entries are
skipped and counted in the search result.
