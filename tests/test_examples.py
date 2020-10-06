
import os
import json
import pytest
import PhishingTracker


def test_analyzer_examples01(capsys):

    if 'TRAVIS' in os.environ:
        # TravisCI does not permit outbound connections
        return
    else:
        analyzers = 'all'

    reference = 'https://www.google.com'

    PhishingTracker.PhishingTracker(debug=True).main(
        reference=reference,
        analyzers=analyzers,
        pathname='/tmp',
        filename='../examples/examples01.yml'
    )

    captured = capsys.readouterr().out.rstrip()
    data = json.loads(captured)

    assert 'analyzers_report' in data
    assert 'reference' in data['analyzers_report']
    assert 'reports' in data['analyzers_report']
