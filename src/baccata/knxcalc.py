"""ETS <ParameterCalculation>: JavaScript that derives parameter values.

Products use these for values ETS must compute rather than store — most often
hidden flags that a <choose> then tests, so skipping them renders the wrong
pages. Each calculation names its inputs (LParameters) and outputs
(RParameters) by alias, and an LRTransformation computes the outputs from the
inputs. The reverse direction (RLTransformation, an edit of an output pushed
back onto the inputs) is not run: those outputs are hidden helper parameters,
never editable in the form.

All of a program's calculations are compiled once into a single JS function so
a refresh costs one duktape call, not one per calculation.
"""
import json, re

try:
    import dukpy
except ImportError:                  # calculations are skipped, not fatal:
    dukpy = None                     # the defaults still render

ALIAS = re.compile(r'^[A-Za-z_$][A-Za-z0-9_$]*$')


def _source(prog):
    """The program's calculations as one `calc(v)` JS function, or ''.

    Each calculation runs in its own closure, so two of them may use the same
    alias names, and writes go back into `v` so a later calculation sees the
    result of an earlier one."""
    if prog._calcjs is None:
        blocks = []
        for c in prog.calcs:
            refs = c.lparams + c.rparams
            if not all(a and ALIAS.match(a) for a, _ in refs):
                continue             # unusable alias: skip this calculation
            decl = ''.join(f'var {a}=v[{json.dumps(i)}];' for a, i in refs)
            back = ''.join(f'out[{json.dumps(i)}]=v[{json.dumps(i)}]={a};'
                           for a, i in c.rparams)
            blocks.append(f'(function(){{{decl}\n{c.lr}\n{back}}})();')
        prog._calcjs = ('function calc(v){var out={};' + ''.join(blocks)
                        + 'return out;}') if blocks else ''
    return prog._calcjs


def _js(v):
    """A stored parameter value as the JS script expects it: a number where
    it looks like one, else the string."""
    try:
        return int(v)
    except (TypeError, ValueError):
        pass
    try:
        return float(v)
    except (TypeError, ValueError):
        return '' if v is None else str(v)


def apply(prog, values):
    """`values` with every calculated parameter recomputed from it."""
    src = _source(prog)
    if not src or dukpy is None:
        return values
    ins = {pid: _js(values.get(pid)) for _, pid in prog.calc_inputs}
    key = tuple(ins.items())
    if key not in prog._calc:
        try:
            out = json.loads(dukpy.evaljs(
                [src, 'JSON.stringify(calc(dukpy["v"]))'], v=ins))
        except Exception:            # a script we cannot run: keep the
            out = {}                 # defaults rather than lose the device
        prog._calc[key] = {k: str(int(v) if isinstance(v, bool) else v)
                           for k, v in out.items() if v is not None}
    return values | prog._calc[key]
