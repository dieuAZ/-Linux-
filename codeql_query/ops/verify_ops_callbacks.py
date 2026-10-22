import csv
import sys

with open(sys.argv[1], newline='', encoding='utf-8') as stream:
    rows = list(csv.DictReader(stream))
checks = [
 ('ops_callback_field_positive', 'ops_framework_read', 'ops_framework_release'),
 ('ops_callback_private_positive', 'ops_framework_private_read', 'ops_framework_private_release'),
 ('ops_callback_container_positive', 'ops_callback_container_read', 'ops_callback_container_release'),
]
for key, read, release in checks:
    selected = [r for r in rows if r['runtime_object_key'] == key + ':parameter:0'
                and r['use_function'] == read and r['free_function'] == release]
    assert selected, key
    if 'container' not in key:
        assert any(int(r['use_callback_depth']) > 0 and int(r['free_callback_depth']) > 0
                   for r in selected), key
assert not any(r['runtime_object_key'].startswith('ops_callback_field_negative:') and
               r['use_function'] == 'ops_framework_read' and
               r['free_function'] == 'ops_framework_release' for r in rows)
assert all(r['concurrency_evidence'] == 'ops_framework_overlap_requires_review' for r in rows)
print('PASS: ops callback private field, private getter, container recovery, helper calls, different hosts')
