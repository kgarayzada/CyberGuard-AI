"""Upload-boundary tests for ZIP validation and extraction. Synthetic archives only."""
import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.archive import MAX_FILE, ArchiveError, extract


def zipped(entries, compression=zipfile.ZIP_DEFLATED):
    """entries: {name: str|bytes}. A trailing slash makes a directory entry."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression) as z:
        for name, content in entries.items():
            z.writestr(name, content)
    return buffer.getvalue()


class Extraction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.destination = self.root / 'source'

    def run_extract(self, data, destination=None):
        archive = self.root / 'upload.zip'
        archive.write_bytes(data)
        return extract(archive, destination or self.destination)

    def reject(self, data, destination=None):
        with self.assertRaises(ArchiveError):
            self.run_extract(data, destination)
        return self.destination

    def test_nested_project_extracts_with_counts(self):
        stats = self.run_extract(zipped({
            'app/main.py': 'print("hello")\n',
            'app/util/helper.py': 'VALUE = 1\n',
            'README.md': '# demo\n',
        }))
        self.assertEqual(stats['files'], 3)
        self.assertEqual(stats['bytes'], len('print("hello")\n') + len('VALUE = 1\n') + len('# demo\n'))
        self.assertEqual((self.destination / 'app/main.py').read_text(), 'print("hello")\n')
        self.assertEqual((self.destination / 'app/util/helper.py').read_text(), 'VALUE = 1\n')

    def test_directory_entries_are_created(self):
        stats = self.run_extract(zipped({'assets/': '', 'assets/logo.txt': 'x'}))
        self.assertEqual(stats['files'], 1)
        self.assertTrue((self.destination / 'assets').is_dir())

    def test_nothing_is_written_outside_the_destination(self):
        archive = self.root / 'upload.zip'
        archive.write_bytes(zipped({'a/b/c.py': 'pass\n'}))
        before = sorted(p.name for p in self.root.iterdir())
        extract(archive, self.destination)
        after = sorted(p.name for p in self.root.iterdir())
        self.assertEqual(after, sorted(before + ['source']))

    def test_destination_must_not_already_exist(self):
        self.destination.mkdir(parents=True)
        self.reject(zipped({'a.py': 'pass\n'}))

    def test_stored_entries_are_accepted(self):
        stats = self.run_extract(zipped({'a.py': 'pass\n'}, compression=zipfile.ZIP_STORED))
        self.assertEqual(stats['files'], 1)

    def test_unsupported_compression_is_rejected(self):
        self.reject(zipped({'a.py': 'pass\n'}, compression=zipfile.ZIP_BZIP2))

    def test_not_a_zip_is_rejected(self):
        self.reject(b'this is plainly not a zip archive')

    def test_directory_only_archive_is_rejected(self):
        self.reject(zipped({'emptydir/': ''}))


class UnsafePaths(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def reject(self, name):
        archive = self.root / 'upload.zip'
        archive.write_bytes(zipped({name: 'pass\n'}))
        with self.assertRaises(ArchiveError):
            extract(archive, self.root / 'source')
        self.assertFalse((self.root / 'source').exists())

    def test_deeply_nested_traversal(self):
        self.reject('a/b/../../../escape.py')

    def test_single_dot_component(self):
        self.reject('a/./b.py')

    def test_overlong_path(self):
        self.reject('a' * 181 + '.py')

    def test_control_characters(self):
        self.reject('bad\x01name.py')

    def test_trailing_space(self):
        self.reject('trailing /file.py')

    def test_reserved_device_name_in_subdirectory(self):
        self.reject('src/COM1.py')

    def test_alternate_data_stream(self):
        self.reject('file.py:stream')


class SizeLimits(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def reject(self, data):
        archive = self.root / 'upload.zip'
        archive.write_bytes(data)
        with self.assertRaises(ArchiveError):
            extract(archive, self.root / 'source')

    def test_single_file_over_the_per_file_limit(self):
        # Incompressible, so only the per-file size rule can trigger.
        self.reject(zipped({'big.bin': os.urandom(MAX_FILE + 1024)}))

    def test_high_compression_ratio(self):
        # 1 MiB of zeros: well under the per-file limit, far over the 200:1 ratio.
        self.reject(zipped({'bomb.txt': b'\0' * (1024 * 1024)}))

    def test_ordinary_compressible_source_is_allowed(self):
        archive = self.root / 'upload.zip'
        archive.write_bytes(zipped({'app.py': 'x = 1\n' * 500}))
        stats = extract(archive, self.root / 'source')
        self.assertEqual(stats['files'], 1)


if __name__ == '__main__':
    unittest.main()
