"""Verify the intentionally empty public package boundary."""

import cybersecgpt.datasets as datasets


def test_package_exports_no_implementation_api() -> None:
    assert datasets.__all__ == ()
    assert datasets.__doc__ == "CyberSecGPT dataset governance package boundary."
