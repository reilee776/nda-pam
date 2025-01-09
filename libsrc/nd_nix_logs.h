#ifndef _ND_NIX_LOGS_H__
#define _ND_NIX_LOGS_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdarg.h>


#include "nd_utils.h"
#include "../common.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/')+1) : __FILE__)
#define nd_log(level, fmt, ...) nd_pam_devlog(level, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__)
void nd_pam_archive_log (struct _msg_header_ header, struct _archive_log logitem ,char * product_nm );

void nd_pam_write_back_log(char* file_name,struct _msg_header_ * header, char * body_data);

void nd_pam_log_to_JSON(struct _msg_header_ header,char * product_nm, char * agtAuthNo, char* agtId, char* action_type, char* session_status, char * current_user, char * ipAddress, char * sessionKey, char * log_result_data, char *fmt, ... );

void nd_pam_sulog_to_JSON(struct _msg_header_ header,char * product_nm, char * agtAuthNo, char* agtId, char * account, char * switch_account, char * su_command, char * client_ip, char * sessionkey, char* collectlogbuffer);

void nd_pam_session_log_to_JSON(struct _msg_header_ header,char * product_nm, char * agtAuthNo, char* agtId, char *prefix, char* session_id, char* account, int uid, int gid, bool isConsole, char* ipAddr, long time, char * session_key, char* collectlogbuff);


void nd_pam_log(struct _msg_header_ header, char * product_nm, char * agtAuthNo, char* agtId,  char* action_type, char* session_status, char * current_user, char * ipAddress, char * sessionKey, char * log_result_data, char *fmt, ... );

void nd_pam_sulog(struct _msg_header_ header,char * product_nm, char * agtAuthNo, char* agtId,  char * account, char * switch_account, char * su_command, char * client_ip, char * sessionkey, char* collectlogbuffer);

void nd_pam_session_log(struct _msg_header_ header,char * product_nm, char * agtAuthNo, char* agtId, char *prefix, char* session_id, char* account, int uid, int gid, bool isConsole, char* ipAddr, long time, char * session_key, char* collectlogbuff);

void nd_pam_devlog(int level, char* filename, int line, const char *fmt, ...);



#endif// _ND_NIX_LOGS_H__
