from attackpath.scoring import score_node


def test_known_service_scores_above_default():
    telnet = score_node({"name": "telnet", "product": "", "version": ""})
    unknown = score_node({"name": "madeup", "product": "", "version": ""})
    assert telnet["score"] > unknown["score"]


def test_score_has_reasons():
    s = score_node({"name": "ftp", "product": "vsftpd", "version": "2.3.4"})
    assert s["reasons"]
    assert 0 <= s["likelihood"] <= 1
