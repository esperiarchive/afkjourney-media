"""Stable published names; revisions and checksums belong in manifests."""
from pathlib import PurePosixPath
import re

POLICY = 'stable-readable'


def stable_path(value, revision=None, resource_path=None, readable_stem=None):
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or '\\' in value or ':' in value:
        raise ValueError('Unsafe published media path: ' + value)
    stem = path.stem
    if revision and stem.endswith('.' + revision):
        stem = stem[:-(len(revision) + 1)]
    # Native extraction adds a resource identity to otherwise ambiguous stems.
    # Keep that identity in metadata and use the known resource's own name.
    if readable_stem or (re.search(r'(?:__[0-9a-f]{10}|^[0-9a-f]{10,64})$', stem) and resource_path):
        native = readable_stem or PurePosixPath(resource_path.replace('\\', '/')).stem
        if native and not re.search(r'__[0-9a-f]{10}$', native):
            stem = re.sub(r'[^a-zA-Z0-9._-]+', '_', native).strip('._')
    elif re.search(r'__[0-9a-f]{10}$', stem):
        # The extractor retains the resource basename before its identity tag.
        # The complete export still checks collisions before writing anything.
        stem = stem[:-12]
    if not stem:
        raise ValueError('Empty stable media filename: ' + value)
    return str(path.with_name(stem + path.suffix))


def require_unique(paths):
    seen = {}
    for path in paths:
        folded = path.casefold()
        if folded in seen:
            raise ValueError('Two assets resolve to the same stable filename: ' + seen[folded] + ' / ' + path)
        seen[folded] = path
