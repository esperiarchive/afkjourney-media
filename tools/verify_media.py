"""Verify the generated media collection without downloading or changing assets."""
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relative_name(value):
    require(isinstance(value, str) and value and '\\' not in value, f'Invalid path: {value!r}')
    parts = value.split('/')
    require(not PurePosixPath(value).is_absolute() and ':' not in value
            and all(part not in {'', '.', '..'} for part in parts), f'Unsafe path: {value}')
    return value


def scan(root):
    files, widths, depths, pending, folded = {}, [], [], [(root, 0)], set()
    while pending:
        folder, depth = pending.pop()
        entries = [entry for entry in os.scandir(folder)
                   if entry.name not in {'.git', '.tmp', '__pycache__'}]
        widths.append(len(entries))
        depths.append(depth)
        for entry in entries:
            stat = entry.stat(follow_symlinks=False)
            require(not entry.is_symlink() and not (getattr(stat, 'st_file_attributes', 0) & 0x400),
                    f'Links/reparse points are not allowed: {entry.path}')
            path = Path(entry.path)
            name = path.relative_to(root).as_posix()
            require(name.casefold() not in folded, f'Case collision: {name}')
            folded.add(name.casefold())
            if entry.is_dir(follow_symlinks=False):
                pending.append((path, depth + 1))
            elif entry.is_file(follow_symlinks=False):
                files[name] = stat.st_size
            else:
                raise ValueError(f'Unsupported file type: {name}')
    require(max(widths, default=0) <= 3000, 'A directory exceeds 3,000 entries')
    require(max(depths, default=0) <= 50, 'Directory depth exceeds 50')
    require(max(files.values(), default=0) < 100 * 1024**2, 'A file reaches GitHub\'s 100 MiB limit')
    return files, max(widths, default=0), max(depths, default=0)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            result.update(block)
    return result.hexdigest()


def verify(root, workers=8):
    root = root.resolve()
    files, width, depth = scan(root)
    registry = hashlib.sha256()

    def read(name):
        relative_name(name)
        require(name in files, f'Missing registry file: {name}')
        data = (root/name).read_bytes()
        registry.update(name.encode() + b'\0' + data + b'\0')
        return json.loads(data)

    index, migration, inventory = [read(name) for name in (
        'manifests/index.json', 'manifests/migration.json', 'inventory.json')]
    require(index['schema_version'] == migration['schema_version'] == inventory['schema_version'] == 1,
            'Unsupported registry schema')
    naming = index.get('capture_filename_policy')
    require(naming in {None, 'stable-pose'}
            and migration.get('capture_filename_policy') == naming
            and inventory.get('capture_filename_policy') == naming, 'Capture filename policies differ')
    shards = index['entries']
    require(len(shards) == len(set(shards)), 'Repeated registry shard')
    require(migration['shards'] == shards and migration['mapping_fields'] == ['source_reference', 'reference'],
            'Migration contract differs from the registry')
    rows = []
    for shard in shards:
        require(re.fullmatch(r'manifests/entries/[0-9a-f]{2}\.json', shard), f'Unexpected shard: {shard}')
        payload = read(shard)
        require(payload['schema_version'] == 1, f'Unsupported shard schema: {shard}')
        for row in payload['entries']:
            require(re.fullmatch(r'[0-9a-f]{64}', row['id']) and row['id'][:2] == Path(shard).stem,
                    f'Wrong identity shard: {row.get("path")}')
            rows.append(row)
    require(len(rows) == index['count'] == inventory['files'], 'Registry count mismatch')
    require(len({row['id'] for row in rows}) == len(rows), 'Duplicate asset identity')
    require(len({row['path'] for row in rows}) == len(rows), 'Duplicate asset path')
    require(len({row['source_reference'] for row in rows}) == len(rows), 'Duplicate source reference')

    categories, classifications, voices = Counter(), Counter(), Counter()
    total_bytes = 0
    for row in rows:
        name = relative_name(row['path'])
        require(name.startswith(('images/', 'audio/', 'support/')), f'Unexpected asset root: {name}')
        require(name in files and files[name] == row['bytes'], f'Missing asset or wrong byte size: {name}')
        require(row['delivery'] in {'frontend', 'media'}, f'Unknown delivery: {name}')
        expected_reference = row['source_reference'] if row['delivery'] == 'frontend' else 'assets/' + name
        require(row['reference'] == expected_reference, f'Wrong published reference: {name}')
        for field in ('sha256', 'source_sha256'):
            require(re.fullmatch(r'[0-9a-f]{64}', row[field]), f'Invalid {field}: {name}')
        transform = json.dumps([row['source_sha256'], row['transform']],
                               ensure_ascii=False, separators=(',', ':')).encode()
        revision = hashlib.sha256(transform).hexdigest()[:16]
        stable = naming == 'stable-pose' and row['category'] in {'dialogue_portraits', 'player_presets'}
        require(row['revision'] == revision, f'Wrong manifest revision: {name}')
        if not stable:
            require(Path(name).stem.endswith('.' + revision), f'Wrong filename revision: {name}')
        relative_name(row['source_path'])
        categories[row['category']] += 1
        total_bytes += row['bytes']
        if row['category'] == 'dialogue_portraits':
            kind, model, pose = row['classification'], row['model'], row['pose']
            require(kind in {'playable', 'npc', 'mobs', 'unclassified'}, f'Unknown portrait kind: {name}')
            bucket = str(row['unit_id']) if kind == 'playable' else hashlib.sha256(model.encode()).hexdigest()[:2]
            suffix = '' if stable else '.' + revision
            expected = f'images/dialogue_portraits/{kind}/{bucket}/{model}/{pose}{suffix}.webp'
            require(name == expected, f'Wrong portrait layout: {name}')
            require(row.get('classification_evidence') in {'playable_roster', 'source_resource', 'unclassified'},
                    f'Missing portrait classification evidence: {name}')
            classifications[kind] += 1
        elif row['category'] == 'player_presets':
            preset = row['preset']
            require(preset['gender'] in {'male', 'female'}, f'Unknown preset gender: {name}')
            require(re.fullmatch(r'default|s0[1-8]', preset['group']), f'Unknown preset group: {name}')
            suffix = '' if stable else '.' + revision
            expected = f'images/player_presets/{preset["group"]}/{preset["gender"]}/{preset["id"]}/{row["pose"]}{suffix}.webp'
            require(name == expected, f'Wrong player preset layout: {name}')
            require(row.get('capture_job') and preset.get('prefab_guid') and preset.get('recipe_sha256'),
                    f'Missing player capture provenance: {name}')
        elif row['category'] == 'voice':
            language = row['language']
            require(language in {'cn', 'en', 'jp', 'kr'}, f'Unknown voice language: {name}')
            require(name.startswith(f'audio/{language}/{row["unit_id"]}/'), f'Wrong voice layout: {name}')
            voices[language] += 1

    payloads = {name for name in files if name.startswith(('images/', 'audio/', 'support/'))}
    require(payloads == {row['path'] for row in rows}, 'Unregistered payload files in media directories')
    require(total_bytes == inventory['bytes'], 'Inventory byte count mismatch')
    require(dict(categories) == inventory['categories'], 'Inventory categories differ')
    require(dict(classifications) == inventory['portrait_classifications'], 'Inventory classifications differ')

    def check(row):
        require(digest(root/row['path']) == row['sha256'], f'Asset SHA-256 mismatch: {row["path"]}')

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for number, _ in enumerate(pool.map(check, rows), 1):
            if number % 3000 == 0:
                print(f'Verified media hashes {number}/{len(rows)}', flush=True)

    return {
        'schema_version': 1, 'valid': True, 'assets_checked': len(rows),
        'sha256_verified': True, 'payload_bytes': total_bytes,
        'registry_sha256': registry.hexdigest(), 'registry_shards': len(shards),
        'categories': dict(sorted(categories.items())),
        'portrait_classifications': dict(sorted(classifications.items())),
        'voices_by_language': dict(sorted(voices.items())),
        'largest_file_bytes': max(files.values()), 'maximum_directory_entries': width,
        'maximum_directory_depth': depth, 'git_file_size_limit_pass': True,
        'unregistered_payload_files': 0, 'source_assets_modified': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    require(args.workers > 0, 'Workers must be positive')
    report = verify(args.root, args.workers)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(encoded, encoding='utf-8', newline='\n')
    print(encoded)


if __name__ == '__main__':
    main()
