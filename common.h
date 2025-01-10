#ifndef _COMMON_H__
#define _COMMON_H__

#define _POSIX_C_SOURCE 200112L

#include <netinet/in.h>
#define IPV4_BUFFER_SIZE 	16
#define NONE_STRING 		"NONE"
#define MAX_OPMODE_LEN 		4
#define MAX_EMERGENCYMODE_LEN 	8

#define MAX_SEND_DATA 		1024
#define MAX_RECV_DATA 		1024
#define MAX_ENV_STR_LEN 	1024
#define MAX_LOG_LEN 		1024
#define MAX_ACCOUNT_LEN 	128

#define DEFAULT_TIMEOUT 	180

#define UNIQUE_ID_LENGTH 	16

#define ND_UUID_LENGTH		40

#define ND_PREFIX_MAX_LEN       32
#define ND_AGENTID_MAX_LEN      16
#define ND_AGTAUTHNO_MAX_LEN    16
#define ND_USERNUM_MAX_LEN	32
#define ND_TIME_MAX_LEN		40
#define ND_CONNECTTYPE_MAX_LEN  16
#define ND_SOURCEIP_MAX_LEN     16
#define ND_LASTAUTHTYPE_MAX_LEN 32
#define ND_SECUR_STEP_NO_MAX_LEN 4
#define ND_SYSACCOUNT_MAX_LEN   128
#define ND_HIWAREACCOUNT_MAX_LEN 128
#define ND_SWITCHUSER_MAX_LEN   128
#define ND_LOGMSG_MAX_LEN       256
#define ND_LOGRESULT_MAX_LEN	16

#define ND_CERT_TP_CODE_MAX_LEN	4
#define ND_CERT_APP_TP_CODE_MAX_LEN 4
#define ND_CERT_APP_SUCES_FAIL_YN_MAX_LEN 4
#define ND_CERT_STEP_SEQ_NO_MAX_LEN 8


#define MAX_LINE_LENGTH 	1024
#define MAX_KEY_LENGTH 		128
#define MAX_VALUE_LENGTH 	256

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define VENDER_NM 		"netand"
#define PRODUCT_NM 		"hiagt"

#define BIN_DIR 		"bin"
#define DATE_DIR 		"data"
#define CONFIG_DIR 		"conf"
#define RULE_DIR 		"rule"
#define LOG_DIR 		"log"
#define SESSION_DIR 		"sess"

#ifdef _RROTOTYPE_DEFINE
#define CONFIG_FILE 		"config.dat"
#define SESSION_FILE 		"session.dat"
#define SULOG_FILE 		"sulog.dat"
#define RULE_FILE 		"rule.dat"
#define COMMON_RULE_FILE	"common-rule"
#define SURULE_FILE 		"su_rule.dat"
#endif //_RROTOTYPE_DEFINE

#define PAM_PRODUCT_NM					"nda-pam"

#define CONFIG_FILE 					"nda-pam-config.conf"

#define BACKUP_LOG_FILE 				"nda-pam-backup.log"
#define BACKUP_SESSION_LOG_FILE 			"nda-pam-session-backup.log"
#define BACKUP_SULOG_FILE 				"nda-pam-sulog-backup.dat"

#define BACKUP_LOG_FILE_WITHOUT_EXTENSION                "nda-pam-backup"
#define BACKUP_SESSION_LOG_FILE_WITHOUT_EXTENSION        "nda-pam-session-backup"
#define BACKUP_SULOG_FILE_WITHOUT_EXTENSION              "nda-pam-sulog-backup"

#define LOGFILE_EXTENSION				".log"

#define BACKUP_LOG_LOCK_FILE 				"nda-pam-backup.lock"
#define BACKUP_SESSION_LOG_LOCK_FILE 			"nda-pam-session-backup.lock"
#define BACKUP_SULOG_LOCK_FILE 				"nda-pam-sulog-backup.lock"


#define DEBUG_LOG_FILE 					"nda-pam.log"

#define RULE_FILE 					"nda-pam-rule.dat"
#define COMMON_RULE_FILE				"common-rule"
#define SURULE_FILE 					"nda-pam-su-rule.dat"

#define SHARED_DATA_KEY 				"my_shared_data"

#define TMP_PATH 					"tmp"
#define PIPE_NM 					"nd_spam_fifo"

#define PAM_PIPE_FILE TMP_PATH 	"/" PIPE_NM

#ifdef _RROTOTYPE_DEFINE
#define PAM_SETTING_FILE 	"/" VENDER_NM "/" CONFIG_DIR "/" CONFIG_FILE
#define PAM_SESSION_FILE 	"/" VENDER_NM "/" SESSION_DIR "/" SESSION_FILE
#define PAM_RULE_FILE 		"/" VENDER_NM "/" RULE_DIR "/" RULE_FILE
#define PAM_SURULE_FILE 	"/" VENDER_NM "/" RULE_DIR "/" SURULE_FILE
#define PAM_SULOG_FILE 		"/" VENDER_NM "/" LOG_DIR "/" SULOG_FILE
#endif //_PROTOTYPE_DEFINE

#define PAM_SETTING_FILE 	"/" PRODUCT_NM "/" CONFIG_DIR "/" CONFIG_FILE

#define PAM_RULE_FILE 		"/" PRODUCT_NM "/" RULE_DIR "/" RULE_FILE
#define PAM_SURULE_FILE 	"/" PRODUCT_NM "/" RULE_DIR "/" SURULE_FILE
#ifdef _OLD_SRC
#define PAM_BACKUP_SULOG_FILE 	"/" PRODUCT_NM "/" DATE_DIR "/" PAM_PRODUCT_NM "/" BACKUP_SULOG_FILE
#define PAM_BACKUP_LOG_FILE 	"/" PRODUCT_NM "/" DATE_DIR "/" PAM_PRODUCT_NM "/" BACKUP_LOG_FILE
#define PAM_BACKUP_SESSION_LOG_FILE "/" PRODUCT_NM "/" DATE_DIR "/" PAM_PRODUCT_NM "/" BACKUP_SESSION_LOG_FILE
#else
#define PAM_BACKUP_SULOG_FILE 	"/" PRODUCT_NM "/" DATE_DIR "/" PAM_PRODUCT_NM "/"  BACKUP_SULOG_FILE_WITHOUT_EXTENSION
#define PAM_BACKUP_LOG_FILE 	"/" PRODUCT_NM "/" DATE_DIR "/" PAM_PRODUCT_NM "/"  BACKUP_LOG_FILE_WITHOUT_EXTENSION
#define PAM_BACKUP_SESSION_LOG_FILE "/" PRODUCT_NM "/" DATE_DIR "/" PAM_PRODUCT_NM "/"  BACKUP_SESSION_LOG_FILE_WITHOUT_EXTENSION
#endif //_OLD_SRC

#define PAM_BACKUP_SULOG_LOCK_FILE 	"/" PRODUCT_NM "/" DATE_DIR "/" PAM_PRODUCT_NM "/" BACKUP_SULOG_LOCK_FILE
#define PAM_BACKUP_LOG_LOCK_FILE 	"/" PRODUCT_NM "/" DATE_DIR "/" PAM_PRODUCT_NM "/" BACKUP_LOG_LOCK_FILE
#define PAM_BACKUP_SESSION_LOCK_LOG_FILE "/" PRODUCT_NM "/" DATE_DIR "/" PAM_PRODUCT_NM "/" BACKUP_SESSION_LOG_LOCK_FILE

#define PAM_LOG_FILE 		"/" PRODUCT_NM "/" LOG_DIR "/" DEBUG_LOG_FILE



#define PAM_LOOPIPADDR "127.0.0.1"

#define SESSION_ID_LENGTH 16

#define SERVICE_SSHD_NAME "sshd"
#define PAM_CONF_KEY_SERVERIP "SERVER_IP"
#define PAM_CONF_KEY_SERVERPORT "SERVER_PORT"

/*
	//fail count
*/
#define FAIL_COUNT_FILE "/tmp/pam_fail_count"
#define MAX_FAILED_ATTEMPTS 3
#define COUNTER_FILE "/var/log/pam_fail_count"

#define MAX_LOG_SIZE 1024

#define STR_SU "su"
#define STR_SUL "su-l"

#define HIWARE_SECRETKEY_FORMAT			"HIWARE_SECRET_KEY=%s"
#define HIWARE_ACTUAL_NAME_FORMAT 		"HIWARE_ACTUAL_NAME=%s"
#define HIWARE_SESSION_KEY_FORMAT 		"HIWARE_SESSION_KEY=%s"
#define HIWARE_AGTAUTHNO_KEY_FORMAT 	"HIWARE_AGTAUTH_NO=%s"
#define HIWARE_SU_ACTUAL_NAME_FORMAT 	"HIWARE_SU_ACTUAL_NAME=%s"
#define HIWARE_LOGIN_TYPE_FORMAT 		"HIWARE_LOGIN_TYPE=%s"
#define HIWARE_ACCOUNT_FORMAT 			"HIWARE_SYSTEM_ACCOUNT=%s"
#define HIWARE_REMOTE_ADDR 				"HIWARE_REMOTE_ADDR=%s"
#define HIWARE_SSH_CLIENT_IP 			"HIWARE_SSH_CLIENT_IP=%s"
#define HIWARE_SSH_CLIENT_PORT 			"HIWARE_SSH_CLIENT_PORT=%s"
#define HIWARE_SSH_SERVER_IP			"HIWARE_SSH_SERVER_IP=%s"
#define HIWARE_SSH_SERVER_PORT  		"HIWARE_SSH_SERVER_PORT=%s"
#define HIWARE_SSH_SERVER_PORT2         "HIWARE_SSH_SERVER_PORT=%d"
#define HIWARE_USER_NUMBER_FORMAT		"HIWARE_USER_NUMBER=%s"
#define HIWARE_NOT_CONNECTAPI_FORMAT	"HIWARE_BYPASS=%s"

#define PAM_BAK_SSH_SERVER_IP        	"HIWARE_SSH_CLIENT_IP"
#define PAM_BAK_SSH_SERVER_PORT      	"HIWARE_SSH_SERVER_PORT"
#define PAM_BAK_SSH_CLIENT_IP        	"HIWARE_SSH_CLIENT_IP"
#define PAM_BAK_SSH_CLIENT_PORT      	"HIWARE_SSH_CLIENT_PORT"


#define DB_PATH "/src/beetle/pam/nd_nix_pam/nd_nix_pam.db"

#define ND_PREFIX_LOGIN "NDLOGIN"
#define ND_PREFIX_LOGOUT "NDLOGOUT"
#define ND_HIWARE_ACTUALNM_KEY "HIWARE_ACTUAL_NAME"

#define ND_SESSION_KEY "ND_SESSION_KEY"

#define MAX_KEY_LEN 1024
#define MAX_URL_LEN 1024
#define MAX_USERID_LEN 256
#define MAX_USERPW_LEN 256

#define SSH_PORT "16" // Hexadecimal for port 22

///////////////////////////////////////////////////////////////
/*
	<TRACE ITEM>
*/

//[MODE]
#define MODE_ON		1
#define MODE_OFF	0

//[LOGGING]
#define LOGGING_ON	1
#define LOGGING_OFF	0

//[PAM_CERT_TP_CODE : PAM 인증 상세 코드]
#define PAM_LOGIN	"01"
#define PAM_LOGOUT	"02"
#define PAM_SU_LOGIN	"03"
#define PAM_SU_LOGOUT	"04"
//#define PAM_LOGINFAIL	"03"
//#define PAM_SU		"04"



#define HEADER_PAM_AGENT_ID 	7
#define HEADER_PAM_MESSG_CODE	6
#define HEADER_PAM_MSG_REQ_TYPE 1

//[PAM_CERT_RST_CODE : PAM 인증 결과 코드]
#define PAM_AUTH_SUCCESS "1"
#define PAM_AUTH_FAIL	 "2"

//[AGT_AUTH_TP_CODE : AGT 권한 구분 코드]
#define PAM_AGT_AUTH_CODE "3"

//[AGT_CONN_FORM_TP_CODE : 접속 방식 코드]
#define PAM_CONN_BYPASS  "1"   //우회 접속
#define PAM_CONN_CONSOLE "2"   //CONSOLE

//[SECUR_STEP_NO : 보안단계번호]
#define PAM_SECUR_STEP_PCAP	"1"
#define PAM_SECUR_STEP_NDSHELL	"2"
#define PAM_SECUR_STEP_PAM	"3"

//[PAM_CERT_DTL_CODE : PAM 인증 상세 작업 코드]
#define PAM_CERT_DTL_AUTH_OS	"01"
#define PAM_CERT_DTL_AUTH_HIWAREAUTH	"02"
#define PAM_CERT_DTL_AUTH_TWOFACT	"03"
#define PAM_CERT_DTL_AUTH_PAM_RULE	"04"
#define PAM_CERT_DTL_AUTH_SAM_RULE	"05"

#define PAM_ACT_RULE_ALLOW	1
#define PAM_ACT_RULE_DENY	2

//[SVR_CONN_FAIL_RSN_CODE : 접속 인증 실패]
#define PAM_SVR_FAIL_OS_AUTH_FAIL	"04"
#define PAM_SVR_FAIL_HI_AUTH_FAIL	"05"
#define PAM_SVR_FAIL_TF_AUTH_FAIL	"06"
#define PAM_SVR_FAIL_MISSING_INFO	"07"
#define PAM_SVR_FAIL_UNAUTH_ACCESS      "09"
#define PAM_SVR_FAIL_HIWARE_DOWNTIME    "12"
//

//[SVR_CONN_RST_TP_CODE]
#define PAM_SVR_CONN_RST_TP_CODE_NORMAL_SUCCESS		"1"
#define PAM_SVR_CONN_RST_TP_CODE_NORMAL_FAILED		"2"
#define PAM_SVR_CONN_RST_TP_CODE_EMERGC_SUCCESS		"3"
#define PAM_SVR_CONN_RST_TP_CODE_EMERGC_FAILED		"4"


/*
	//
*/
#define ENV_SSHCONNECTION 	"SSH_CONNECTION"
#define ENV_HIWARE_SESSIONKEY 	"HIWARE_SESSION_KEY"
#define ENV_HIWARE_AGTAUTHNO  	"HIWARE_AGTAUTH_NO"
#define ENV_HIWARE_HOME		"HIAGT_HOME"
#define ENV_HIWARE_USER_NUMBER	"HIWARE_USER_NUMBER"

#define ND_PAM_VERSION	"0.0.01.001"

extern char *g_sDataIssueKey;
extern char *g_sDataRandomKey;
extern char *g_sDataAuthKey;
extern char *g_sDataSecretKey;
extern char *g_sUserNumber;

extern char * g_sDataUserLoginResult;
extern char * g_sDataTemporaryAccessKey;
extern char * g_sDataHiwareUserNumber;

extern char * g_sDataProductNm;
extern char * g_sDataRootDir;

extern char g_sDataRandomUrl[MAX_URL_LEN];
extern char g_sDataUserLoginUrl[MAX_URL_LEN];
extern char g_sDataSystemLoginUrl[MAX_URL_LEN];
extern char g_sDataTwoFactLoginIrl[MAX_URL_LEN];
extern int g_nDataSshPort;

extern char * g_sConfFilePath;

char g_sDataAgentId[2];

/*
		// su log format
		// <now session account>|<switch account>|<su command>|<tty>|<tty master>|<tty session client ip>|//<tty session client port>
*/
#define ND_SULOG_FORMAT "%s|%s|%s|%s|%s|%s|"

//#define ND_PAMLOG_FORMAT_V2 "<$@>iMsgType@>%d@>iMsgCode@>%d@>iMsgVerMaj@>%d@>iMsgVerMin@>%d@>iMsgTotalSize@>%d@>action_type@>%s@>session_status@>%s@>account@>%s@>ipaddr@>%s@>sessionKey@>%s@>message@>%s$>"
#define ND_PAMLOG_FORMAT_V2 "<$@>iMsgType@>%d@>iMsgCode@>%d@>iMsgVerMaj@>%d@>iMsgVerMin@>%d@>iMsgTotalSize@>%d@>action_type@>%s@>session_status@>%s@>account@>%s@>ipaddr@>%s@>sessionKey@>%s@>message@>%s$>"
#define ND_SULOG_FORMAT_V2 "<$@>iMsgType@>%d@>iMsgCode@>%d@>iMsgVerMaj@>%d@>iMsgVerMin@>%d@>iMsgTotalSize@>%d@>account@>%s@>switch_account@>%s@>su_command@>%s@>client_ip@>%s@>time@>%ld@>%s$>"
#define ND_SESSIONLOG_FORMAT_V2 "<$@>iMsgType@>%d@>iMsgCode@>%d@>iMsgVerMaj@>%d@>iMsgVerMin@>%d@>iMsgTotalSize@>%d@>prefix@>%s@>session_id@>%s@>account@>%s@>uid@>%d@>gid@>%d@>isconsole@>%d@>ipaddr@>%s@>time@>%ld@>%s$>"

#define ND_LOGIN_MFA_ACCEPTED_MSG_FORMAT "Accepted hiware Multi-Prompt Verification/pam for %s from %s %s"
#define ND_LOGIN_MFA_EXCLUDED_MSG_FORMAT "Excluded by policy hiware Multi-Prompt Verification/pam for %s from %s %s"

#define PAM_DATA_SESSIONID "ND_PAM_SESSION_ID"
#define PAM_DATA_FAILCNT "ND_PAM_FAILCOUNT"

/*
	// default port <api port>
*/
#define PAM_HIAUTH_DEFAULT_PORT 1004

/*
	// config section key
*/
#define SECTION_NM_PAM_CONF "PAM_CONF"
#define SECTION_NM_HIAUTH_CONF "HIAUTH_CONF"
#define SECTION_NM_HILOGER_CONF "HILOGER_CONF"
#define SECTION_NM_TWOFACT_CONF "TOWFACT_CONF"
#define SECTION_NM_SYSLOGIN_CONF "SYSLOGIN_CONF"

/*
	// config value data
*/
#define SET_MODE_ON 	"ON"
#define SET_MODE_OFF 	"OFF"
#define SET_MODE_BYPASS "BYPASS"
#define SET_MODE_BLOCK 	"BLOCK"

#define CONF_VALUE_YES 	"YES"
#define CONF_VALUE_NO 	"NO"

#define CONF_VALUE_JSON "JSON"
#define CONF_VALUE_TEXT "TEXT"

/*
	// config section value
*/
#define PAM_CONF_KEY_PAM_MODE 		"PAM_MODE"
#define PAM_CONF_KEY_SU_CONTROL 	"PAM_SU_CONTROL"
#define PAM_CONSOLE_CONTROL 		"PAM_CONSOLE_CONTROL"
#define PAM_LOG_MODE 			"PAM_LOG_MODE"
#define PAM_AUTHSVR_LINKAGE 		"PAM_AUTHSVR_LINKAGE"
#define PAM_AUTHSVR_EMERGENCY_ACTION 	"PAM_AUTHSVR_EMERGENCY_ACTION"
#define PAM_AUTHSVR_TIMEOUT 		"PAM_AUTHSVR_TIMEOUT"
#define PAM_AUTHSVR_USESSL 		"SERVER_USE_SSL"

#define PAM_CONF_KEY_SERVERIP 		"SERVER_IP"
#define PAM_CONF_KEY_SERVERPORT 	"SERVER_PORT"
#define PAM_CONF_KEY_SERVERUSE 		"SERVER_USE"

#define PAM_CONF_KEY_TRANS_FORMAT 	"TRANS_FORMAT"

#define PAM_CONF_KEY_SYSTEM_ID 		"SYSTEM_ID"
#define PAM_CONF_KEY_SYSTEM_PW 		"SYSTEM_PW"

#define PAM_LOGIN_RESULT_TRUE		"true"
#define PAM_LOGIN_RESULT_FALSE		"false"


//contentSimpleType
#define PAM_JSON_KEY_NM_CONTENTSIMPLETYPE	"contentSimpleType"
#define PAM_JSON_KEY_VALUE_RET_SUCCESS		"AdditionalVerificationRequiredResult"
#define PAM_JSON_KEY_VALUE_RET_FAILED		"ErrorResult"
#define PAM_JSON_KEY_VALUE_RET_REQREG		"RegisterOtpRequiredResult"

/*
	// JSON KEY
*/
#define PAM_JSON_KEY_NM_RESULTCODE	"resultCode"
#define PAM_JSON_KEY_NM_CONTENT		"content"
#define PAM_JSON_KEY_NM_LOGINRESULT	"loginResult"
#define PAM_JSON_KEY_NM_TMPACCESSKEY	"temporaryAccessKey"

/*
	//string format
*/
#define STR_FORMAT_CHECK_USER "USER_CHECK|%s"
#define STR_FORMAT_HIWARE_AUTH "HIAUTH|%s|%s|%s"
#define STR_FORMAT_OTP_AUTH "AUTH_OTP_REQ|%s"
#define STR_FORMAT_FIDO_AUTH "AUTH_FIDO_REQ|%s"
#define STR_FORMAT_SU_CHECK_USER "SU_CHECK|%s|%s"

/*
	// log size define
*/
#define MAX_STRINGS 10
#define MAX_STRING_LENGTH 1024 // 각 문자열의 최대 길이
#define BUFFER_SIZE ((size_t)2 * 1024 * 1024 * 1024)

/*
	// log header size define
*/
#define MSG_HEADER_SIZE 8

/*
	// pack msg
*/
#define PACK_MSG_MAJ_VER 0
#define PACK_MSG_MIN_VER 0

/*
	// pack msg type
*/
enum _pack_msg_type_
{
	PACK_MSG_TYPE_NONE = 0,
	PACK_MSG_TYPE_SSH_AUTH,
	PACK_MSG_TYPE_SSH_SESSION,
	PACK_MSG_TYPE_SU_AUTH,
	PACK_MSG_TYPE_SU_SESSION,

	PACK_MSG_TYPE_MAX
};

/*
	// pack msg code
*/
enum _pack_msg_code_
{
	PACK_MSG_CODE_NONE = 0,
	PACK_MSG_CODE_SESSION_OPEN,
	PACK_MSG_CODE_SESSION_CLOSE,
	PACK_MSG_CODE_ACCEPTED_PASSWD,
	PACK_MSG_CODE_REJECT_PASSWD,
	PACK_MSG_CODE_ACCEPTED_HIAUTH,
	PACK_MSG_CODE_REJECT_HIAUTH,
	PACK_MSG_CODE_ACCEPTED_MFA,
	PACK_MSG_CODE_REJECT_MFA,
	PACK_MSG_CODE_ATTEMPTS_SWITCH,
	PACK_MSG_CODE_REJECT_SWITCH,

	PACK_MSG_CODE_MAX
};

/*
	// log index
*/
enum log_index
{
	NDLOG_INF 	= 0,
	NDLOG_WAN	,
	NDLOG_DBG	,
	NDLOG_TRC	,
	NDLOG_ERR	,
	NDLOG_MAX
};

/*
	// log level index
*/
enum log_level_index
{
	LOG_LEVEL_NONE = 0,
	LOG_LEVEL_WARN,
	LOG_LEVEL_ERR,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_TRACE,
	LOG_LEVEL_MAX
};

/*
	// session log type
*/
enum sessionlog_type
{
	NDSLOG_LOGIN = 0,
	NDSLOG_LOGOFF,
	NDSLOG_MAX
};

/*
	// hiware auth index
*/
enum hiware_auth_index
{
	HIAUTH_ID = 0,
	HIAUTH_PW,
	HIAUTH_MAX
};

/*
	// auth type index
*/
enum auth_purpose_index
{

	AUTH_PURPOS_CONSOLE = 0,
	AUTH_PURPOS_TERMINAL,
	AUTH_PURPOS_SU,
	AUTH_PURPOS_MAX
};

/*
	// operation mode index
*/
enum st_oper_mode_index
{
	OPER_MODE_NODE = 0,
	OPER_MODE_ON,
	OPER_MODE_OFF,
	OPER_MODE_MAX
};

/*
	// pam auth process index
*/
enum st_pam_process_index
{

	PAM_PROCESS_NONE = 0,
	PAM_PROCESS_OSAUTH,
	PAM_PROCESS_SUAUTH,
	PAM_PROCESS_HIWARE,
	PAM_PROCESS_TWOFACT,
	PAM_PROCESS_MAX
};

/*
	// pam support two-fact auth index
*/
enum st_pam_twofact_extauth
{
	PAM_EXTAUTH_NONE = 0,
	PAM_EXTAUTH_OTP,
	PAM_EXTAUTH_FIDO,
	PAM_EXTAUTH_MAX
};

/*
	//
*/
enum st_pam_switch_allow
{

	PAM_SWITCH_ALLOW = 0,
	PAM_SWITCH_DENY,

	PAM_SWITCH_MAX
};

/*
	//
*/
enum st_pam_user_rule_action
{
	PAM_USER_RULE_ACT_NONE	=0,
	PAM_USER_RULE_ACT_ALLOW	,
	PAM_USER_RULE_ACT_DENY	,

	PAM_USER_RULE_ACT_MAX
};

/*
	// hiware auth base output structure
*/
struct st_hiauth_item
{
	int index;
	const char item[128];
};

extern struct st_hiauth_item nd_hiauth_item[];

/*
	// hiware auth out data
*/
struct st_hiauth_input_data
{

	char sHiAuthId[128];
	char sHiAuthPw[128];
};

/*
	// result of auth process
*/
struct st_auth_result_data
{
	int ret;
	int nextprocess;
	int currentprocess;
	int AuthExt;
};

/*
	// log level base structure
*/
struct st_log_level
{
	int nLevel;
	const char stLevel[8];
};

/*
	// session type base structure
*/
struct st_sesslog_type
{
	int nType;
	const char stType[8];
};

extern struct st_log_level nd_log_level[];
extern struct st_sesslog_type nd_slog_type[];

/*
	// login user information
*/
struct pam_user_info
{
	char username[256]; // user name
	char switchusernname[256];
	int switch_allow;
	bool bNeedtoEnvUpdata;
	char switchuserActualNm[256];
	char realpwd[256];
	bool isConsole;					// console
	uid_t uid;						// user UID
	gid_t gid;						// GID
	char *tty;						// tty
	char home_directory[512];		// user home directory
	char shell[256];				// shell
	char auth_method[256];			// auth method
	const char *encrypted_password; // 암호화된 비밀번호
	char *ip_address;				// IP 주소 (IPv6까지 지원)
	char *service;
	time_t login_time;	 // 접속 시간
	char session_id[64]; // 세션 ID
	int login_status;	 // 로그인 상태 (예: 0 = 성공, 1 = 실패)
	int auth_fail_count; // 인증 실패 횟수
	char mfa_info[256];	 // 추가 인증 정보 (MFA 등)
	char agtAuthNo[16];
	char agtId[16];
	
};

/*
	// two-fact login index ??
*/
enum pam_twofact_index
{
	TWOFACT_NONE = 0,
	TWOFACT_OTP,
	TWOFACT_FIDO,

	TWOFACT_MAX
};

/*
	// pam config information
*/
struct st_pam_conf
{

	//[PAM_CONF]
	int pam_operate_mode;
	int su_operate_mode;
	char console_operate_mode[MAX_OPMODE_LEN];
	char authsvr_linkage[MAX_OPMODE_LEN];
	char authsvr_emergency_act[MAX_EMERGENCYMODE_LEN];
	int authsvr_timeout;

	//[HIAUTH_CONF]
	char auth_ip[IPV4_BUFFER_SIZE];
	int auth_port;
	int auth_server_use;

	//[TWOFACT_CONF]
	int twofact_type;
};

/*
	// pam auth request information
*/
struct pam_auth_req_info
{

	char *username;
	char *userpwd;
	char *hiwarename;
	char *hiwarepwd;
	char *remoteipaddr;
};

/*
	// pam rule information
*/
struct pam_rule_info
{

	char username[256];
	char ipaddr[IPV4_BUFFER_SIZE];
};

/*
	// connect remote client information
*/
typedef struct
{
	char ip[INET_ADDRSTRLEN];
	char port[6]; // 최대 포트 번호는 5자리 + null terminator
	char tty[64]; // TTY의 최대 길이
} pam_client_info;

/*
	// pam operation mode in config file
*/
typedef struct
{
	char pam_mode[4];		// "ON" 또는 "OFF"
	char pam_su_control[4]; // "ON" 또는 "OFF"
} pam_config;

/*
	// log header struct
*/
#ifdef _OLD_SRC
struct _msg_header_
{
	unsigned char iProductType;

	unsigned char iMsgType;

	unsigned char iMsgCode;

	unsigned char iMsgVerMaj;

	unsigned char iMsgVerMin;

	unsigned int iMsgTotalSize;
	
} __attribute__((packed)) ;
#else //_OLD_SRC
struct _msg_header_
{
        unsigned char sReqTraceId[36];

	unsigned short  sAgentId;

        unsigned char iMsgType;

        unsigned char iMsgCode;

        unsigned char iMsgVer[10];

        unsigned int iMsgTotalSize;

} __attribute__((packed)) ;
#endif //_OLD_SRC

#ifdef _OLD_SRC
struct _archive_log
{
	char prefix[ND_PREFIX_MAX_LEN];
	char agentId[ND_AGENTID_MAX_LEN];
	char agtAuthNo[ND_AGTAUTHNO_MAX_LEN];
	char pamAgtAuthNo[ND_AGTAUTHNO_MAX_LEN];
	char userNumber[ND_USERNUM_MAX_LEN];
	int  sslPort;
	char sessionKey[ND_UUID_LENGTH];
	char time[ND_TIME_MAX_LEN];
	char connect_type[ND_CONNECTTYPE_MAX_LEN];
	char sourceIp[ND_SOURCEIP_MAX_LEN];
	char last_auth_type[ND_LASTAUTHTYPE_MAX_LEN];
	char secur_step_no[ND_SECUR_STEP_NO_MAX_LEN];
	char sys_account[ND_SYSACCOUNT_MAX_LEN];
	char hiware_account[ND_HIWAREACCOUNT_MAX_LEN];
	char switch_sys_account[ND_SWITCHUSER_MAX_LEN];
	char message[ND_LOGMSG_MAX_LEN];
	char result[ND_LOGRESULT_MAX_LEN];

	char certTpCode[ND_CERT_TP_CODE_MAX_LEN];
	char certAppTpCode[ND_CERT_APP_TP_CODE_MAX_LEN];
	char certSucesFailYn[ND_CERT_APP_SUCES_FAIL_YN_MAX_LEN];
	char certStepSeqNo[ND_CERT_STEP_SEQ_NO_MAX_LEN];
};
	
#else //OLD_SRC
struct _archive_log
{
	char    svrConnStartTime[ND_TIME_MAX_LEN];
        char    svrConnEndTime[ND_TIME_MAX_LEN];
        char    svrConnRstTpCode [4];
        char    svrConnFailRsnCode [4];
        char    agtNo[16];
        char    agtConnFormTpCode[4];
        char    agtAuthNo[ND_AGTAUTHNO_MAX_LEN];
        char    portNo[8];
        char    userIp[ND_SOURCEIP_MAX_LEN];
        char    securStepNo[ND_SECUR_STEP_NO_MAX_LEN];
        char    svrConnSessKey[ND_UUID_LENGTH];
        char    connAcctId[ND_SYSACCOUNT_MAX_LEN];
	char 	switchAcctId[ND_SYSACCOUNT_MAX_LEN];
        char    pamAgtAuthNo[ND_AGTAUTHNO_MAX_LEN];
        char    userNo[18];
        char    pamCertDtlCode[4];
	char    pamCertDtlAuthCode[4];

        char    certTpCode[ND_CERT_TP_CODE_MAX_LEN];
        char    certAppTpCode[ND_CERT_APP_TP_CODE_MAX_LEN];
        char    certSucesFailYn[ND_CERT_APP_SUCES_FAIL_YN_MAX_LEN];
        char    certStepSeqNo[ND_CERT_STEP_SEQ_NO_MAX_LEN];

};

#endif 


#define MSG_HEADER_SIZE 8

#define MAX_IP_LIST 10
#define MAX_ACCOUNT_LIST 10

typedef struct {
	int priNo;
	const char * agtAuthNo;
	char **ipList;
	int action;
	int logging;
	char **account;
	int ipCount;
	int accountCount;
} Rule;

typedef struct {
	Rule *rules;
	int ruleCount;
} PamPolicy;

// Structure definition
typedef struct {
        char *current_user;
        char *target_user;
        char *remote_host;
        char *tty;
        int type; // 1: Console, 2: SSH, 3: su
} SessionInfo;

#endif //_COMMON_H__
