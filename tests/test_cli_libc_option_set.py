"""CG-02: pin the CLI ``--libc`` surface against drift.

The agreed, reviewed surface: exactly the seven ret2libc/exploit-building
commands carry ``--libc``; ``onegadget`` takes a REQUIRED ``libc`` positional;
``libc-id`` takes no libc positional (it consumes optional leaked-address
flags). Analysis commands construct analyzers with no libc input, so they
deliberately do NOT carry a non-functional ``--libc`` (threading a real one is
S6 detector-depth work).
"""

import click

import supwngo.cli as cli_mod

EXPECTED_LIBC_OPTION_COMMANDS = {
    "autopwn",
    "explain",
    "exploit",
    "pwn",
    "rop",
    "solve",
    "template",
}


def _commands():
    return cli_mod.cli.commands


def _has_libc_option(cmd):
    return any(
        opt == "--libc"
        for p in cmd.params
        if isinstance(p, click.Option)
        for opt in p.opts
    )


def _libc_arguments(cmd):
    return [
        p
        for p in cmd.params
        if isinstance(p, click.Argument) and "libc" in p.name.lower()
    ]


def test_libc_option_present_exactly_on_agreed_set():
    actual = {name for name, cmd in _commands().items() if _has_libc_option(cmd)}
    assert actual == EXPECTED_LIBC_OPTION_COMMANDS


def test_onegadget_has_required_libc_positional():
    onegadget = _commands()["onegadget"]
    libc_args = _libc_arguments(onegadget)
    assert len(libc_args) == 1
    assert libc_args[0].required is True


def test_libc_id_has_no_libc_positional_or_option():
    libc_id = _commands()["libc-id"]
    assert _libc_arguments(libc_id) == []
    assert not _has_libc_option(libc_id)


def test_analysis_commands_have_no_libc_option():
    # Threading a real --libc into these analyzers is S6 detector-depth work; a
    # non-functional flag must not be added in the meantime.
    for name in (
        "heap-analysis",
        "integer-analysis",
        "leaks",
        "decompile",
        "cfg",
        "dataflow",
    ):
        cmd = _commands()[name]
        assert not _has_libc_option(cmd), name
