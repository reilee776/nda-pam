#!/bin/bash

# 변경사항 추가
git add .

# 커밋
if [ -z "$1" ]; then
  echo "Please provide a commit message."
  exit 1
fi
git commit -m "$1"

# 푸시
git push origin main

echo "Git repository updated successfully."
