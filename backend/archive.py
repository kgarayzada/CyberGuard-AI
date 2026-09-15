"""Bounded ZIP validation. Uploaded code is never executed."""
from pathlib import Path
import re, stat, zipfile

MAX_UPLOAD = 20 * 1024 * 1024
MAX_EXPANDED = 80 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_FILES = 2000

class ArchiveError(ValueError): pass

def extract(archive: Path, destination: Path):
    try:
        with zipfile.ZipFile(archive) as z:
            entries = z.infolist()
            if not entries or not any(not x.is_dir() for x in entries):
                raise ArchiveError('The archive contains no files.')
            if len(entries) > MAX_FILES: raise ArchiveError('Archive exceeds the 2,000 entry limit.')
            total, seen, checked = 0, set(), []
            for info in entries:
                name = info.orig_filename
                parts = name.rstrip('/').split('/')
                if (not name or '\\' in name or name.startswith('/') or len(name) > 180
                    or any(p in ('', '.', '..') or p.endswith((' ', '.')) or re.search(r'[<>:"|?*\x00-\x1f\x7f]', p)
                           or re.match(r'^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)', p, re.I) for p in parts)):
                    raise ArchiveError('Archive contains an unsafe path.')
                key = '/'.join(parts).casefold()
                if key in seen: raise ArchiveError('Archive contains duplicate paths.')
                seen.add(key)
                mode = info.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ArchiveError('Archive links and special files are not supported.')
                if info.flag_bits & 1: raise ArchiveError('Password-protected ZIP archives are not supported.')
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ArchiveError('Unsupported ZIP compression method.')
                total += info.file_size
                if info.file_size > MAX_FILE or total > MAX_EXPANDED or info.file_size > max(1, info.compress_size) * 200:
                    raise ArchiveError('Archive exceeds extraction size or compression-ratio limits.')
                target = destination.joinpath(*parts).resolve()
                if not target.is_relative_to(destination.resolve()): raise ArchiveError('Unsafe extraction path.')
                checked.append((info, target))
            destination.mkdir(parents=True, exist_ok=False)
            actual = 0
            for info, target in checked:
                if info.is_dir(): target.mkdir(parents=True, exist_ok=True); continue
                target.parent.mkdir(parents=True, exist_ok=True)
                count = 0
                with z.open(info) as source, target.open('xb') as out:
                    while chunk := source.read(65536):
                        count += len(chunk); actual += len(chunk)
                        if count > MAX_FILE or actual > MAX_EXPANDED: raise ArchiveError('Extraction size limit exceeded.')
                        out.write(chunk)
            return {'files': sum(not x.is_dir() for x in entries), 'bytes': actual}
    except ArchiveError: raise
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, NotImplementedError) as exc:
        raise ArchiveError('The uploaded file is not a valid ZIP archive.') from exc
