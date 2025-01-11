#!/bin/bash

# PAM 모듈 빌드 및 Git 업데이트 스크립트
set -e  # 오류 발생 시 즉시 종료

# 변수 설정
REPO_DIR="/src"           # Git 소스 디렉토리
BUILD_OUTPUT_DIR="/output" # 빌드 결과 디렉토리
GIT_BRANCH="main"          # Git 브랜치 이름
GIT_COMMIT_MESSAGE="Update: PAM module build results"

# 빌드 실행
echo "Starting build process..."
cd $REPO_DIR
make clean
make

# 빌드 결과를 /output 디렉토리에 복사
echo "Copying build results to $BUILD_OUTPUT_DIR..."
mkdir -p $BUILD_OUTPUT_DIR
cp -r *.so $BUILD_OUTPUT_DIR || true

# Git 상태 확인
echo "Preparing to update Git repository..."
cd $REPO_DIR

# Git 설정 (필요 시 사용자 정보 설정)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Git 작업 디렉토리에 변경 내용 반영
git add -A
git commit -m "$GIT_COMMIT_MESSAGE"

# 원격 리포지토리에 푸시
echo "Pushing changes to Git repository..."
git push origin $GIT_BRANCH

echo "Build and Git update completed successfully!"

