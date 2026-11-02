import sudare

LOG = "<34>Oct 29 14:11:40 fw01 sshd[22]: Failed password for jdoe from 192.0.2.10 port 4 user=jdoe\n"


def test_mask_hides_values_and_unmask_restores_them():
    r = sudare.mask(LOG, mode="strict")
    for value in ("jdoe", "fw01", "192.0.2.10"):
        assert value not in r.masked
    user = next(t for t, kind, _ in r.tokens() if kind == "username")
    assert r.unmask(f"{user} logged in") == "jdoe logged in"
    assert r.parser == "syslog3164"


def test_tokens_never_expose_values():
    r = sudare.mask(LOG)
    assert all("jdoe" not in "".join(t) for t in r.tokens())
    assert "jdoe" not in repr(r)


def test_bad_mode_is_a_value_error():
    try:
        sudare.mask(LOG, mode="loose")
    except ValueError as e:
        assert "strict" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_parsers_listed():
    assert {"cef", "leef", "syslog3164", "winxml", "raw"} <= set(sudare.parsers())
