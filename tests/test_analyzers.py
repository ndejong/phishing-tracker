
import json
import pytest
import PhishingTracker


def test_analyzer_whois(capsys):
    analyzers = ['whois']
    reference = 'https://www.google.com'
    __test_analyzer_meta(analyzers, capsys, reference=reference)

def test_analyzer_dig(capsys):
    analyzers = ['dig']
    reference = 'https://www.google.com'
    __test_analyzer_meta(analyzers, capsys, reference=reference)

def test_analyzer_http(capsys):
    analyzers = ['http']
    reference = 'https://www.google.com'
    __test_analyzer_meta(analyzers, capsys, reference=reference)

def test_analyzer_https(capsys):
    analyzers = ['https']
    reference = 'https://www.google.com'
    __test_analyzer_meta(analyzers, capsys, reference=reference)

def test_analyzer_https_certificate(capsys):
    analyzers = ['https_certificate']
    reference = 'https://www.google.com'
    __test_analyzer_meta(analyzers, capsys, reference=reference)

# def test_analyzer_smtp(capsys):
#     analyzers = ['smtp']
#     reference = 'https://www.google.com'
#     __test_analyzer_meta(analyzers, capsys, reference=reference)


def __test_analyzer_meta(analyzers, capsys, reference='https://www.google.com'):
    PhishingTracker.PhishingTracker(debug=True).main(
        reference=reference,
        analyzers=analyzers,
        pathname='/tmp'
    )

    captured = capsys.readouterr().out.rstrip()
    data = json.loads(captured)

    assert 'analyzers_report' in data
    assert 'analyzer_report_sets' in data['analyzers_report']
    assert 'reference' in data['analyzers_report']
    assert 'reports' in data['analyzers_report']
