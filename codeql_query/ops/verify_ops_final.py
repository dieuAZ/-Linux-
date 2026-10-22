import csv
import sys

with open(sys.argv[1], newline='', encoding='utf-8') as stream:
    rows = list(csv.DictReader(stream))

for name in ['ops_return_callback_positive', 'ops_return_dispatch_positive', 'ops_self_positive']:
    assert any(row['runtime_object_key'] == name + ':parameter:0'
               or (name == 'ops_return_dispatch_positive' and
                   row['runtime_object_key'] == name + ':parameter:1')
               for row in rows), ('missing', name)
for name in ['ops_return_callback_negative', 'ops_return_dispatch_negative']:
    expected_use = 'read' if 'callback' in name else 'use'
    assert not any((name in row['free_argument_trace'] or name in row['use_argument_trace']
                    or row['runtime_object_key'].startswith(name + ':'))
                   and row['use_method'] == expected_use and row['free_method'] == 'release'
                   for row in rows), ('unexpected different-object pair', name)
assert any(row['use_method'] == row['free_method'] == 'use'
           and row['free_function'] == row['use_function'] == 'ops_self_method'
           for row in rows), 'self/self callback missing'
print('PASS: ops returned pointers, nested getters, different hosts, self/self method')
