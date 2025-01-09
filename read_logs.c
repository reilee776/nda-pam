#include <stdio.h>
#include <string.h>

struct _msg_header_ {
    unsigned char iProductType;
    unsigned char iMsgType;
    unsigned char iMsgCode;
    unsigned char iMsgVerMaj;
    unsigned char iMsgVerMin;
    unsigned int iMsgTotalSize;
} __attribute__((packed));

void nd_pam_write_back_log(char* file_name, struct _msg_header_ *header, char *body_data) {
    FILE *file = fopen(file_name, "ab+");
    if (file == NULL)
        return;

    size_t written = fwrite(header, sizeof(struct _msg_header_), 1, file);
    if (written != 1) {
        fclose(file);
        return;
    }

    fprintf(file, "%s", body_data);
    fclose(file);
}

void read_log_file(char* file_name) {
	FILE *file = fopen(file_name, "rb");
	if (file == NULL) {
		printf("파일을 열 수 없습니다.\n");
		return;
	}

	struct _msg_header_ header;
	char body_data[1024]; // 본문 데이터 버퍼

	while (fread(&header, sizeof(struct _msg_header_), 1, file) == 1) {
		// 본문 데이터 읽기
		fread(body_data, sizeof(char), header.iMsgTotalSize - sizeof(struct _msg_header_), file);
		body_data[header.iMsgTotalSize - sizeof(struct _msg_header_)] = '\0'; // 문자열 종료

		// 읽은 데이터 출력
		printf("Product Type: %u, Msg Type: %u, Msg Code: %u, Msg Ver: %u.%u, Total Size: %u, Body: %s\n",
		       header.iProductType, header.iMsgType, header.iMsgCode,
		       header.iMsgVerMaj, header.iMsgVerMin, header.iMsgTotalSize, body_data);
	}

	fclose(file);
}

int main(int argc, char *argv[]) {

	if (argc < 2) {
        	fprintf(stderr, "Usage: %s <file_name>\n", argv[0]);
        	return 0;
    	}

	char* file_name = argv[1];
	read_log_file(file_name);

    	return 0;
}

