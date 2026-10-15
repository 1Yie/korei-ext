"""Demo hook — appends 喵～ to the end of every model answer.

`husk_hooks.py` next to this file is vendored from `<repo>/sdks/python/` —
copy it along when installing the plugin into a plugins dir.
"""

from husk_hooks import on, rewrite_text, run


@on("on_response")
def meow(p):
    text = (p.get("text") or "").rstrip()
    if text and not text.endswith("喵～"):
        return rewrite_text(text + " 喵～")


run()
