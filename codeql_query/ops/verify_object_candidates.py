"""Check value-flow evidence without executing the dangling-access C fixture."""
import csv
import sys

with open(sys.argv[1], newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream))

keys = {row["runtime_object_key"] for row in rows}
for name in ["ops_test_positive_same_object", "ops_identity_alias",
             "ops_identity_position", "ops_identity_nested_root",
             "ops_identity_nested_siblings", "ops_identity_callback_positions"]:
    assert name + ":parameter:0" in keys, name

for name in ["ops_test_negative_different_objects", "ops_identity_two_allocations",
             "ops_identity_reassignment"]:
    assert not any(name in key or name in row["free_argument_trace"] or
                   name in row["use_argument_trace"]
                   for row in rows for key in [row["runtime_object_key"]]), name

position = [row for row in rows
            if row["runtime_object_key"] == "ops_identity_callback_positions:parameter:0"]
assert any(row["free_root_parameter_index"] == "1" and
           row["use_root_parameter_index"] == "0" and
           row["use_method"] == "read" for row in position)
assert any("ops_identity_one_allocation" in row["free_argument_trace"] for row in rows)
assert any(row["free_wrapper_depth"] == "1" and
           row["use_wrapper_depth"] == "2" for row in rows)
assert any(row["runtime_object_key"] == "ops_identity_nested_siblings:parameter:0" and
           row["freed_object_path"] == ".b.c" and row["used_object_path"] == ".b.d"
           for row in rows)
assert all(row["object_relation"] == "may_same_runtime_object" for row in rows)
print("PASS: shared origin, aliases, wrappers, callback positions, allocations, reassignment, siblings")
print(f"Validated {len(rows)} candidate rows")
