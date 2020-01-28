
import os
import tempfile
import pytest
from unittest.mock import patch
import PhishingTracker


def test_name_exist():
    pt = PhishingTracker
    assert pt.NAME is not None


def test_version_exist():
    pt = PhishingTracker
    assert pt.VERSION is not None
