#!/bin/bash

# 소스 다운로드 디렉토리 설정
SOURCE_DIR="/opt/sources"
mkdir -p $SOURCE_DIR

# 패키지 다운로드 함수
download_package() {
    local package_name=$1
    local version_command=$2
    local version_cleanup_command=$3
    local download_url_template=$4

    # 설치된 버전 확인
    local raw_version=$(eval "$version_command")
    if [[ -n "$version_cleanup_command" ]]; then
        raw_version=$(echo "$raw_version" | eval "$version_cleanup_command")
    fi

    # 버전 확인
    if [[ -z $raw_version ]]; then
        echo "[ERROR] $package_name is not installed or version could not be determined."
        return 1
    fi

    echo "[INFO] $package_name version: $raw_version"

    # 다운로드 URL 생성
    local download_url=$(echo "$download_url_template" | sed "s/\\\$VERSION/$raw_version/g")
    echo "[INFO] Download URL: $download_url"

    # 다운로드 시도
    wget "$download_url" -P "$SOURCE_DIR"
    if [[ $? -ne 0 ]]; then
        echo "[ERROR] Failed to download $package_name from $download_url."
        return 1
    fi

    echo "[INFO] $package_name downloaded successfully."
}

# 패키지 다운로드
download_package "libuuid-devel" \
    "dnf list installed libuuid-devel | grep libuuid-devel | awk '{print \$2}'" \
    "cut -d '.' -f 1,2" \
    "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v\$VERSION/util-linux-\$VERSION.tar.xz"

download_package "json-c-devel" \
    "dnf list installed json-c-devel | grep json-c-devel | awk '{print \$2}'" \
    "cut -d '-' -f 1" \
    "https://s3.amazonaws.com/json-c_releases/releases/json-c-\$VERSION.tar.gz"

download_package "libcurl-devel" \
    "dnf list installed libcurl-devel | grep libcurl-devel | awk '{print \$2}'" \
    "cut -d '.' -f 1,2" \
    "https://curl.se/download/curl-\$VERSION.tar.gz || https://curl.se/download/curl-7.88.1.tar.gz"

download_package "openssl-devel" \
    "dnf list installed openssl-devel | grep openssl-devel | awk '{print \$2}'" \
    "sed 's/^1://; s/-.*//'" \
    "https://www.openssl.org/source/openssl-\$VERSION.tar.gz"

echo "[INFO] All packages processed. Check $SOURCE_DIR for downloaded files."

