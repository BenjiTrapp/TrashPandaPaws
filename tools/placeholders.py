"""`{{NAME}}` substitution for the committed storyboards and scripts.

Shared because both tools/capture_sequence.py and tools/scripted_model.py
need it: neither a storyboard nor a model script can know the beacon id,
which is assigned at check-in. Writing the substitution twice is the
mistake this project's own branch review found in two duplicated flag
tables -- one concept implemented twice, and the copies drifted.
"""

import re

# Delimited, not guessed. The first version matched any run of capitals,
# so captions mentioning SMB, LDAP, NTLM and MSSQL were read as unfilled
# placeholders and the capture refused to start before taking a frame.
_PLACEHOLDER = re.compile(r"\{\{([A-Za-z][A-Za-z0-9_]*)\}\}")


def fill(text, values):
    """Substitute `{{NAME}}` in raw JSON text, refusing what is left over.

    Into the text rather than into each parsed field, so a placeholder
    works wherever it appears -- a `js` expression, a caption, a wait
    selector, a command inside a model's tool call. An unfilled one is an
    error: a tour shot against a beacon literally called BEACON_ID would
    succeed at every step and be useless, which is the kind of failure
    only noticed after the whole capture run.
    """
    for name, value in values.items():
        if any(ch in str(value) for ch in '"\\'):
            raise ValueError(
                "the value for %s contains a quote or backslash (%r) and "
                "would break the JSON it is substituted into"
                % (name, value))
        text = text.replace("{{%s}}" % name, str(value))
    left = sorted(set(_PLACEHOLDER.findall(text)))
    if left:
        raise ValueError("unfilled placeholder(s): %s" % ", ".join(left))
    return text
