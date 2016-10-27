import glob
from os.path import dirname, basename

# Create a list consisting of all attack classes names in this package
__all__ = []
modules = glob.glob(dirname(__file__) + "/*.py")
for m in modules:
    c = str(basename(m)[:-3])
    if not c.startswith('__') and not c.startswith('Base') and c.endswith('Attack'):
        __all__.append(c)
