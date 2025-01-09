#!/bin/bash

# Red Hat Subscription 등록 스크립트

# 사용자 입력 확인
if [ $# -ne 2 ]; then
    echo "Usage: $0 <RedHat_Username> <RedHat_Password>"
    exit 1
fi

USERNAME=$1
PASSWORD=$2

# Red Hat Subscription Manager 설치 확인
if ! command -v subscription-manager &>/dev/null; then
    echo "Installing subscription-manager..."
    sudo yum install -y subscription-manager
fi

# 시스템 등록
echo "Registering the system with Red Hat Subscription Manager..."
subscription-manager register --username "$USERNAME" --password "$PASSWORD" --auto-attach

if [ $? -ne 0 ]; then
    echo "System registration failed. Please check your credentials or account status."
    exit 1
fi

# 시스템 등록 상태 확인
echo "Checking subscription status..."
sudo subscription-manager status

# 기본 리포지토리 활성화
echo "Enabling base repositories..."
subscription-manager repos --enable=rhel-8-for-x86_64-baseos-rpms
subscription-manager repos --enable=rhel-8-for-x86_64-appstream-rpms

# 추가 리포지토리 활성화 (필요한 경우)
echo "Enabling optional repositories (if necessary)..."
subscription-manager repos --enable=codeready-builder-for-rhel-8-x86_64-rpms

# 필수 패키지 설치
echo "Installing required packages..."
yum install -y libuuid-devel
yum install -y json-c-devel
yum install -y libcurl-devel
yum install -y openssl-devel

if [ $? -eq 0 ]; then
    echo "All packages installed successfully."
else
    echo "Package installation failed. Please check the errors above."
    exit 1
fi

echo "Red Hat Subscription registration and package installation completed successfully!"
