"""Verify bounded field, private API, and container recovery witnesses."""
import csv
import sys

with open(sys.argv[1], newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream))
keys = {row["runtime_object_key"] for row in rows}
positive = ["ops_transfer_field", "ops_transfer_two_fields", "ops_transfer_private",
            "ops_transfer_private_wrapper", "ops_transfer_container",
            "ops_transfer_nested_field", "ops_transfer_platform", "ops_transfer_pci",
            "ops_transfer_usb", "ops_transfer_i2c", "ops_transfer_spi"]
for name in positive:
    assert name + ":parameter:0" in keys, ("missing positive", name)
for name in ["ops_transfer_field_negative_host", "ops_transfer_field_negative_slot",
             "ops_transfer_private_negative", "ops_transfer_container_negative_member",
             "ops_transfer_container_negative_host", "ops_transfer_nested_negative"]:
    assert name + ":parameter:0" not in keys, ("unexpected negative", name)

with open(sys.argv[2], newline="", encoding="utf-8") as stream:
    evidence = list(csv.DictReader(stream))
assert any("private_data:dev_set_drvdata" in row["transfer_evidence"] for row in evidence)
assert any("container_of:ops_container.first" in row["transfer_evidence"] for row in evidence)
assert any(row["transfer_count"] == "2" and
           row["runtime_object_key"] == "ops_transfer_two_fields:parameter:0"
           for row in evidence)
print(f"PASS: {len(positive)} positive and 6 negative object-transfer cases")
print(f"Validated {len(rows)} candidate rows and {len(evidence)} transfer witnesses")
