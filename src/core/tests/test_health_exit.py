"""Health exit semantics: critical failures fail the check; warnings do not."""

import pytest

from src.core.system_check import CheckResult, SystemChecker


def _checker(results):
    checker = SystemChecker()
    checker.results = results
    return checker


@pytest.mark.unit
def test_critical_failure_fails_the_check(capsys):
    result = _checker([CheckResult(name="db", passed=False, message="broken", critical=True)]).print_results()
    assert result is False


@pytest.mark.unit
def test_non_critical_warning_does_not_fail_the_check(capsys):
    result = _checker([
        CheckResult(name="Directory: logs", passed=False, message="logs/ missing (warning)", critical=False),
        CheckResult(name="python", passed=True, message="ok", critical=True),
    ]).print_results()
    assert result is True
    assert "logs/ missing" in capsys.readouterr().out
