from scripts.cm4_dashboard import status


def test_dashboard_does_not_claim_field_validation_without_evidence(tmp_path):
    info = status(tmp_path)
    assert info['samples'] == 0
    assert info['runtime'] == 'Not checked'
    assert info['wpa3'].startswith('Not tested')
    assert info['prediction'] == 'No result yet'


def test_dashboard_identifies_synthetic_demo(tmp_path):
    import json
    folder = tmp_path / 'data/field/install-check'
    folder.mkdir(parents=True)
    (folder / 'tcn.inference.json').write_text(json.dumps({
        'sessions': [{'prediction': 'fixture_small'}],
    }))
    info = status(tmp_path)
    assert info['prediction'] == 'Synthetic demo: fixture_small'
    assert info['samples'] == 0
    assert info['demo']
    assert info['wpa3'].startswith('Not tested')


def test_empty_real_manifest_is_actionable_error(tmp_path):
    import pytest
    from scripts.cm4_dashboard import inference_command
    folder = tmp_path / 'data/field/cm4'
    folder.mkdir(parents=True)
    model = tmp_path / 'models/cm4_tcn.pt'
    model.parent.mkdir()
    model.touch()
    (folder / 'manifest.csv').write_text('pcap,bssid,client_mac\n')
    with pytest.raises(RuntimeError, match='no sessions'):
        inference_command(tmp_path)
