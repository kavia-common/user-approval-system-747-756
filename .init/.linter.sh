#!/bin/bash
cd /tmp/kavia/workspace/code-generation/user-approval-system-747-756/social_media_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

