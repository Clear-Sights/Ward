"""Pin the suite to THIS checkout's plugin tree.

LOAD-BEARING, not hygiene. `pip install -e .` drops a plain path-append `.pth`
(`.../dist-packages/__editable__.ward-0.1.0.pth`) naming ONE plugin directory, and on a machine
holding both Ward and Ward-Dev that directory is whichever was installed last. Verified: with this
file absent, `python3 -m unittest discover -s tests` run inside /home/user/Ward imported
/home/user/Ward-Dev/plugin/ward/checks.py -- so a full green run said nothing at all about this
checkout. Disarming THIS tree's `evaluate` to `return None` left all 67 security parity tests
passing, with and without -O. A suite that cannot see the code it is meant to test is not evidence
about that code; "absence must not read as green" binds the tests too, not only the checks.

`sys.path[0]` beats the `.pth`'s appended entry. That is sufficient here because this `.pth` is the
plain path-append kind and installs no meta-path finder -- a finder WOULD outrank `sys.path`, and
this alone would not be enough against one.
"""
import os
import sys

_PLUGIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
if _PLUGIN in sys.path:
    sys.path.remove(_PLUGIN)
sys.path.insert(0, _PLUGIN)
