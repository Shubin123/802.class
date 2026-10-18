from scripts.cm4_dashboard import status


def test_dashboard_does_not_claim_field_validation_without_evidence(tmp_path):
    info = status(tmp_path)
    assert info['samples'] == 0
    assert info['runtime'] == 'Not checked'
    assert info['wpa3'].startswith('Not tested')
    assert info['prediction'] == 'No result yet'
