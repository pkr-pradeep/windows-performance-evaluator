import unittest
import tempfile
from pathlib import Path

from app import (
    LARGE_FILE_BYTES,
    LARGE_PROCESS_BYTES,
    file_matches_filters,
    file_size_without_following_symlinks,
    format_size,
    format_checked_rows,
    format_driver_history_details,
    driver_state_has_issue,
    child_directories,
    is_directory_within_root,
    memory_growth_anomaly,
    parse_extensions,
    temperature_anomaly,
)


class FileFilterTests(unittest.TestCase):
    def test_extension_filter_is_case_insensitive(self) -> None:
        extensions = parse_extensions(" .TXT, jpg ")
        self.assertEqual(extensions, {".txt", ".jpg"})
        self.assertTrue(file_matches_filters(Path("Report.TXT"), "", extensions))
        self.assertFalse(file_matches_filters(Path("Report.pdf"), "", extensions))

    def test_name_filter_is_case_insensitive(self) -> None:
        self.assertTrue(file_matches_filters(Path("VideoArchive.mp4"), "archive", set()))
        self.assertFalse(file_matches_filters(Path("VideoArchive.mp4"), "music", set()))

    def test_empty_filters_match_any_file(self) -> None:
        self.assertTrue(file_matches_filters(Path("anything.bin"), "", set()))

    def test_file_size_uses_lstat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory, "sample.bin")
            file_path.write_bytes(b"sample")
            self.assertEqual(file_size_without_following_symlinks(file_path), 6)

    def test_selected_directory_must_be_within_drive_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "drive")
            nested = root / "folder"
            outside = Path(directory, "drive-other")
            nested.mkdir(parents=True)
            outside.mkdir()
            self.assertTrue(is_directory_within_root(str(nested), str(root)))
            self.assertFalse(is_directory_within_root(str(outside), str(root)))

    def test_directory_dropdown_source_lists_direct_children_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "z-folder").mkdir()
            (root / "a-folder").mkdir()
            (root / "file.txt").write_text("not a folder", encoding="utf-8")
            self.assertEqual(
                child_directories(str(root)),
                [str(root / "a-folder"), str(root / "z-folder")],
            )


class DisplayTests(unittest.TestCase):
    def test_large_item_thresholds(self) -> None:
        self.assertEqual(LARGE_FILE_BYTES, 100_000_000)
        self.assertEqual(LARGE_PROCESS_BYTES, 200_000_000)

    def test_size_display_uses_megabytes(self) -> None:
        self.assertEqual(format_size(1_000_000), "1.0 MB")

    def test_checked_rows_are_formatted_as_tab_separated_text(self) -> None:
        self.assertEqual(
            format_checked_rows(
                ("Process", "PID", "Memory"),
                [("browser", "42", "250.0 MB"), ("editor", "7", "300.0 MB")],
            ),
            "Process\tPID\tMemory\nbrowser\t42\t250.0 MB\neditor\t7\t300.0 MB",
        )

    def test_driver_issue_detection_uses_presence_problem_and_status(self) -> None:
        healthy = {
            "present": "True",
            "problem": "0",
            "status": "OK",
        }
        self.assertFalse(driver_state_has_issue([healthy]))
        self.assertTrue(driver_state_has_issue([]))
        self.assertTrue(driver_state_has_issue([{**healthy, "problem": "45"}]))
        self.assertTrue(driver_state_has_issue([{**healthy, "present": "False"}]))
        self.assertTrue(driver_state_has_issue([{**healthy, "status": "Error"}]))

    def test_driver_issue_details_include_attached_windows_event(self) -> None:
        details = format_driver_history_details(
            {
                "details": "Adapter is not present.",
                "is_issue": True,
                "related_events": [
                    {
                        "Time": "2026-10-29T10:00:00+05:30",
                        "Log": "System",
                        "Provider": "Microsoft-Windows-Kernel-PnP",
                        "EventId": 219,
                        "RecordId": "1234",
                        "Message": "Driver could not be loaded.",
                    }
                ],
            }
        )
        self.assertIn("Adapter is not present.", details)
        self.assertIn("Event ID 219", details)
        self.assertIn("Record ID 1234", details)
        self.assertIn("Driver could not be loaded.", details)

    def test_memory_growth_requires_both_size_and_percentage_thresholds(self) -> None:
        self.assertTrue(
            memory_growth_anomaly(
                [(0.0, 400_000_000), (60.0, 500_000_000)]
            )
        )
        self.assertFalse(
            memory_growth_anomaly(
                [(0.0, 400_000_000), (60.0, 490_000_000)]
            )
        )
        self.assertFalse(
            memory_growth_anomaly(
                [(0.0, 800_000_000), (60.0, 900_000_000)]
            )
        )

    def test_temperature_anomaly_uses_absolute_and_rolling_rise_limits(self) -> None:
        self.assertTrue(temperature_anomaly([(0.0, 65.0), (60.0, 75.0)]))
        self.assertTrue(temperature_anomaly([(0.0, 70.0), (5.0, 80.0)]))
        self.assertFalse(temperature_anomaly([(0.0, 60.0), (61.0, 70.0)]))


if __name__ == "__main__":
    unittest.main()
