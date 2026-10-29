#!/bin/bash
# Reference solution: install the reference engine and point /app/iamctl at it,
# then confirm it reproduces the bundled examples.
set -euo pipefail
cd /app
cp /solution/iam_engine.py /app/iam_engine.py
cat > /app/iamctl <<'SH'
#!/bin/sh
exec python3 /app/iam_engine.py "$@"
SH
chmod 755 /app/iamctl
python3 tools/compare.py examples/ex1 examples/ex2 examples/ex3
