import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from vmlinux_to_elf.core.kallsyms import KallsymsFinder
from vmlinux_to_elf.kernel_db.database import DebianRelease, KernelVersion


class ReleaseDateTest(unittest.TestCase):
    def test_extract_db_information_accepts_iso_date_string(self):
        kernel = KernelVersion(
            version_string='6.1.162',
            kernel_source='git',
            release_date='2026-09-03',
            browse_url='source',
            download_url='download',
        )
        kernel_query = MagicMock()
        kernel_query.where.return_value = [kernel]
        debian_query = MagicMock()
        debian_query.where.return_value.order_by.return_value = []
        finder = KallsymsFinder.__new__(KallsymsFinder)
        finder.version_number = '6.1.162'
        finder.elf_machine = 0

        with (
            patch.object(KernelVersion, 'select', return_value=kernel_query),
            patch.object(DebianRelease, 'select', return_value=debian_query),
        ):
            finder.extract_db_information()

        self.assertIsInstance(kernel.release_date, datetime)
        self.assertEqual(kernel.release_date, datetime(2026, 9, 3))


if __name__ == '__main__':
    unittest.main()
