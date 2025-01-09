#!/bin/bash

# 공유 라이브러리 파일 복사
#sudo cp nd_nix_pam.so /usr/lib64/security/
sudo cp nda-pam.so /usr/lib64/security/

echo "nda-pam.so 파일이 /usr/lib64/security/ 디렉토리에 복사되었습니다."
