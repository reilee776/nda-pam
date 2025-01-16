#ifndef _ND_RESTAPI_FUNC_H_
#define _ND_RESTAPI_FUNC_H_
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
#include <json-c/json.h>

#include "nd_utils.h"
#include "../common.h"

#define RSA_KEY_BITS 2048
#define RSA_PADDING RSA_PKCS1_OAEP_PADDING
#define RSA_KEY_SIZE (RSA_KEY_BITS / 8)
#define AES_KEY_SIZE 16 // AES-128 requires 16-byte key
#define AES_BLOCK_SIZE 16

#define EXCEPTION 1
#define RET_SUCCESS 0

#define STRING_CURL_HEADER_CONTENT_TYPE "Content-Type: application/json"
#define STRING_CURL_HEADER_USER_AGENT "User-Agent: hi-dev-checker"
#define STRING_CURL_HEADER_API_TOKEN "API-Token: %s"
#define STRING_CURL_HEADER_SIGNATURE "Signature: %s"
#define STRING_CURL_HEADER_HANDSHAKE_SID "Handshake-Session-Id: %s"

// https://127.0.0.1:11200/hiware/api/v1/auth/pam/login

#define STRING_RANDOM_KEY_URI "/hiware/api/v1/auth/randomKey"
#define STRING_LOGIN_URI "/hiware/api/v1/auth/systemLogin"
#define STRING_USERLOGIN_URI "/hiware/api/v1/auth/pam/login"
#define STRING_TWOFACT_OTP_URI "/hiware/api/v1/auth/pam/additionalVerify"
#define STRING_ALS_HANDSHAKE_URI "/hiware/api/v1/auth/handshake"
#define STRING_ALS_LOGIN_URI "/hiware/api/v1/auth/systemLogin"
#define STRING_PING_URI "/hiware/api/v1/auth/ping"
#define STRING_POLLURI "/sam/access/getEqmtList"
#define STRING_REPOURI "/sam/access/setEqmtStatus"

// #define nd_log(level, fmt, ...) nd_pam_devlog(level, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__)

/*
	//
*/
enum _hi_auth_result
{

	HI_AUTH_RET_FAILED = 0,
	HI_AUTH_RET_SUCCEED,
	HI_AUTH_RET_REQ_REGOTP,

	HI_AUTH_RET_MAX
};

/*
	//
*/
enum _hi_auth_type
{

	HI_AUTH_TYPE_NONE = 0,
	HI_AUTH_TYPE_HIWARE,
	HI_AUTH_TYPE_OTP,
	HI_AUTH_TYPE_FIDO,
	HI_AUTH_TYPE_MAX
};

/*
	//
*/
typedef struct
{

	char *m_data; // 응답 데이터를 저장할 포인터
	size_t size;  // 응답 데이터의 크기
} ApiHttpRes;

/*
	//
*/
typedef struct
{

	char *issueKey;
	char *randomKey;
} Worker;

/*
	//
*/
typedef struct _st_login_result
{

	char authKey[256];
	char userNumber[256];
	char secretKey[256];
} st_login_result;

/*
	//
*/
typedef struct _st_user_login_result
{

	int resultCode;
	char loginResult[8];
	char userId[256];
	char userNumber[8];
	char temporaryAccessKey[256];
	char *errorcode;
	char *message;
	char *contentSimpleType;
	char *certTpCode;
	char *certAppTpCode;
	char *certSucesFailYn;
	char *certStepSeqNo;

} st_user_login_result;

/*
	//
*/
struct st_hiauth_os_login_result
{
	int ret;
};

/*
	//
*/
struct st_hiauth_hiware_login_result
{
	int ret;
	char *errorcode;
	char *message;
	char *certTpCode;
	char *certAppTpCode;
	char *certSucesFailYn;
	char *certStepSeqNo;
	char *contentSimpleType;
};

/*
	//
*/
typedef struct _st_hiauth_twofact_login_result
{
	int resultCode;
	char loginResult[8];
	char userId[256];
	char userNumber[8];
	char temporaryAccessKey[256];
	char *errorcode;
	char *message;
	char *contentSimpleType;
	char *typeCodeName;
	char *certTpCode;
	char *certAppTpCode;
	char *certSucesFailYn;
	char *certStepSeqNo;
} st_hiauth_twofact_login_result;

struct st_hiauth_su_login_result
{
	int ret;
};

struct st_hiauth_su_access_perm_result
{
	int ret;
};

// 매크로 정의
#define SendPostDataWithDefaults(contents, res, url) \
	SendPostData(contents, res, url, "", "", "", 1)

#define SendGetDataWithDefaults(res, url) \
	SendGetData(res, url, "", "", "", 1)

/*
		//
*/
void MakeRdmURL(const char *ip, int port, char *rdmURL, size_t rdmURLSize, int httpsUse);

/*
		//
*/
void MakeLoginURL(const char *ip, int port, char *loginURL, size_t loginURLSize, int httpsUse);

/*
		//
*/
const char *getSecretKey();

/*
		//
*/
void setSeretKey(char *secert_key);

/*
		//
*/
const char *getIssueKey();

/*
		//
*/
void setIssueKey(char *issue_key);

/*
		//
*/
const char *getRandomKey();

/*
		//
*/
void setRandomKey(char *rand_key);

/*
		//
*/
const char *getAuthKey();

/*
		//
*/
void setAuthKey(char *auth_key);

/*
		//
*/
const char *getUserNumber();

/*
		//
*/
void setUserNumber(char *user_number);

/*
	//
*/
char *base64UrlSafeEncode(const unsigned char *input, int length);

/*
		//
*/
char *base64_encode(const unsigned char *input, int length);

/*
		//
*/
char *encPassword(const char *p_sStr, const char *p_sKey);

/*
		//
*/
char *GetSignature(const char *sMethod, const char *url, const char *sData);

/*
		//
*/
void setIssueKey_to_struct(Worker *worker, const char *key);

/*
		//
*/
void setRandomKey_to_struct(Worker *worker, const char *key);

/*
		//
*/
size_t callback_write_memory(void *ptr, size_t size, size_t nmemb, ApiHttpRes *res);

/*
		//
*/
int getRandomKey_Request(Worker *worker);

/*
		//
*/
int SendGetData(ApiHttpRes *pRes, const char *url, const char *sSessID, const char *sSignature, const char *authKey, int iHttpsUse);

/*
		//
*/
bool SendPostData(const char *p_sContents, ApiHttpRes *pRes, const char *url, const char *sSignature, const char *sSessID, const char *authKey, int iHttpsUse);

/*
	//
*/
int parse_JsonResponse_from_twofact_otp_request(const char *res_doc, st_hiauth_twofact_login_result *plogin_result);

/*
		//
*/
int parse_JsonResponse_from_login_request(const char *res_doc, st_user_login_result *plogin_result);

/*
		//
*/
int parse_JsonResponse_from_ramdom_request(const char *json_str, Worker *worker);

/*
		//
*/
// int send_hiware_login_request ( const char * username, const char *passwd );

/*
	//
*/
int requestOSAuthToApiServer(const char *username, const char *password, struct st_hiauth_os_login_result *result);

/*
	//
*/
int requestHiwareAuthToApiServer(const char *username, const char *password, const char *agt_auth_no, struct st_hiauth_hiware_login_result *result);

/*
	//
*/
int requestTwoFactAuthToApiserver(const char *type, const char *temporaryAccessKey, const char *stepNumber, const char *authCode, const char *langCode, st_hiauth_twofact_login_result *result);

/*
	//st_hiauth_su_login_result
*/
int requestSuAuthToApiServer(const char *username, const char *password, struct st_hiauth_su_login_result *result);

/*
	//
*/
int requestSuAccessPermissionsToApiServer(const char *current_user, const char *switch_user, struct st_hiauth_su_access_perm_result *result);

#endif //_ND_RESTAPI_FUNC_H_
