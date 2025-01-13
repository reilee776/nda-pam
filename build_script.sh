# PAM 모듈 빌드 및 Git 업데이트 스크립트
set -e  # 오류 발생 시 즉시 종료

# 변수 설정
REPO_DIR="/src"           # Git 소스 디렉토리
BUILD_OUTPUT_DIR="/output" # 빌드 결과 디렉토리
GIT_BRANCH="main"          # Git 브랜치 이름
GIT_COMMIT_MESSAGE="Update: PAM module build results"

# OS 이름 및 버전 가져오기
OS_NAME=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2 | tr -d '"')
OS_VERSION=$(cat /etc/os-release | grep ^VERSION_ID= | cut -d'=' -f2 | tr -d '"')

# OS 이름과 버전을 합쳐서 사용자 친화적 이름 생성
OS_FRIENDLY_NAME="${OS_NAME}${OS_VERSION}"

# 현재 날짜와 시간을 기준으로 경로 생성
TIMESTAMP=$(date +"%Y-%m-%d-%H-%M-%S")
BUILD_TIMESTAMP_DIR="$BUILD_OUTPUT_DIR/${OS_FRIENDLY_NAME}_$TIMESTAMP"

# 빌드 실행
echo "Starting build process..."
cd $REPO_DIR
make clean
make

# ldd를 사용하여 참조 라이브러리를 복사
echo "Copying linked libraries..."
LIB_COPY_DIR="$BUILD_TIMESTAMP_DIR/lib/nda-pam"
mkdir -p "$LIB_COPY_DIR"
ldd "$BUILD_TIMESTAMP_DIR/nda-pam.so" | awk '{if (NF > 2) print $3}' | while read -r lib; do
    if [ -f "$lib" ]; then
        cp -u "$lib" "$LIB_COPY_DIR"
    fi
done

# 빌드 결과를 OS 및 타임스탬프 디렉토리에 복사
echo "Copying build results to $BUILD_TIMESTAMP_DIR..."
mkdir -p $BUILD_TIMESTAMP_DIR
cp -r *.so $BUILD_TIMESTAMP_DIR || true

# Git 상태 확인
echo "Preparing to update Git repository..."
cd $REPO_DIR

# 빌드 결과를 Git 리포지토리로 이동
mkdir -p "$REPO_DIR/build_results/${OS_FRIENDLY_NAME}_$TIMESTAMP"
cp -r $BUILD_TIMESTAMP_DIR/* "$REPO_DIR/build_results/${OS_FRIENDLY_NAME}_$TIMESTAMP"

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

