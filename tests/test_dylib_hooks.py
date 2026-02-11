"""Tests for FlowPatch.dylib — compiles and runs the ObjC test harness."""

import subprocess
import tempfile
from pathlib import Path

import pytest

DYLIB_SRC = Path(__file__).parent.parent / "flow_patcher" / "patch_dylib.m"
HARNESS_SRC = Path(__file__).parent / "test_dylib.m"


@pytest.fixture(scope="module")
def built_artifacts():
    """Compile the dylib and test harness once per test module."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        dylib = tmp / "FlowPatch.dylib"
        harness = tmp / "test_dylib"

        # Compile dylib
        subprocess.run(
            [
                "clang",
                "-dynamiclib",
                "-framework",
                "Foundation",
                "-framework",
                "CoreData",
                "-arch",
                "arm64",
                "-o",
                str(dylib),
                str(DYLIB_SRC),
                "-install_name",
                "@rpath/FlowPatch.dylib",
            ],
            check=True,
            capture_output=True,
        )

        # Compile test harness
        subprocess.run(
            [
                "clang",
                "-framework",
                "Foundation",
                "-arch",
                "arm64",
                "-o",
                str(harness),
                str(HARNESS_SRC),
            ],
            check=True,
            capture_output=True,
        )

        yield {"dylib": dylib, "harness": harness}


def _run_harness(built_artifacts) -> tuple[str, int]:
    """Run the test harness and return (stdout, exit_code)."""
    result = subprocess.run(
        [str(built_artifacts["harness"]), str(built_artifacts["dylib"])],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout, result.returncode


def _parse_tap(output: str) -> list[dict]:
    """Parse TAP output into a list of {ok, num, desc} dicts."""
    tests = []
    for line in output.strip().split("\n"):
        if line.startswith("ok ") or line.startswith("not ok "):
            ok = line.startswith("ok ")
            rest = line.split(" - ", 1)
            desc = rest[1] if len(rest) > 1 else ""
            tests.append({"ok": ok, "desc": desc})
    return tests


class TestDylibHooks:
    """Run the ObjC test harness and assert individual TAP results."""

    @pytest.fixture(autouse=True)
    def _run(self, built_artifacts):
        self.output, self.exit_code = _run_harness(built_artifacts)
        self.results = _parse_tap(self.output)

    def _assert_test(self, desc_fragment: str):
        """Assert that a test matching desc_fragment passed."""
        matching = [r for r in self.results if desc_fragment in r["desc"]]
        assert matching, f"No test found matching '{desc_fragment}' in output:\n{self.output}"
        for r in matching:
            assert r["ok"], f"FAILED: {r['desc']}\nFull output:\n{self.output}"

    def test_dlopen_succeeds(self):
        self._assert_test("dlopen succeeds")

    def test_boolForKey_returns_yes_for_pro(self):
        self._assert_test("boolForKey: returns YES for isProSubscriptionActive")

    def test_boolForKey_passthrough(self):
        self._assert_test("boolForKey: passes through for non-pro keys")

    def test_setBool_forces_yes(self):
        self._assert_test("setBool:forKey: forces YES")

    def test_purchaserInfo_has_pro_entitlement(self):
        self._assert_test("has injected pro entitlement")

    def test_purchaserInfo_has_lifetime_subscription(self):
        self._assert_test("has Lifetime subscription")

    def test_pro_entitlement_product_id(self):
        self._assert_test("product_identifier is correct")

    def test_pro_entitlement_lifetime_expiry(self):
        self._assert_test("expires_date is null")

    def test_removeObjectForKey_blocked_for_pro(self):
        self._assert_test("removeObjectForKey: blocked for pro key")

    def test_removeObjectForKey_allowed_for_others(self):
        self._assert_test("removeObjectForKey: allowed for non-pro keys")

    def test_objectForKey_passthrough(self):
        self._assert_test("objectForKey: passes through for normal keys")

    def test_all_passed(self):
        """Meta-test: verify zero failures in the harness."""
        assert self.exit_code == 0, f"Harness failed (exit={self.exit_code}):\n{self.output}"
