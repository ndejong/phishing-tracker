
import json
import pytest
import PhishingTracker


def test_analyzer_examples01(capsys):
    analyzers = None
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
    assert 'analyzer_report_sets' in data['analyzers_report']
    assert 'reference' in data['analyzers_report']
    assert 'reports' in data['analyzers_report']
