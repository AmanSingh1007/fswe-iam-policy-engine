#!/bin/bash
# Verifier entry point for the IAM policy engine task.
#
# Stops anything the agent left running, then runs verify_iam.py, which builds
# fresh scenarios, answers them with the reference engine, and runs /app/iamctl
# on each as the unprivileged agent user. The test files are made root-only
# first, so nothing run as the agent can read the reference engine.
# reward.txt is written 0 first and replaced with 1 only if every answer matched.
set -uo pipefail

REWARD=/logs/verifier/reward.txt
mkdir -p /logs/verifier
write_reward() { rm -rf "$REWARD"; printf '%s\n' "$1" > "$REWARD"; }
write_reward 0

pkill -9 -u agent 2>/dev/null
sleep 1
chmod -R go-rwx /tests

RUNDIR=$(mktemp -d /tmp/iam-run.XXXXXX)
chmod 755 "$RUNDIR"
trap 'rm -rf "$RUNDIR"' EXIT

if [ ! -x /app/iamctl ]; then
  echo "VERIFIER: /app/iamctl is missing or not executable"; exit 0
fi

python3 -I /tests/verify_iam.py "$RUNDIR" /logs/verifier/details.json
status=$?

pkill -9 -u agent 2>/dev/null
if [ "$status" -eq 0 ]; then
  write_reward 1
else
  write_reward 0
fi
echo "reward: $(cat "$REWARD")"
exit 0
