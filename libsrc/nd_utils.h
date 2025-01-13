#ifndef ND_UTILS_H
#define ND_UTILS_H
#include <json-c/json.h>
#include <security/pam_ext.h>
#include "../common.h"
//	[etc]
/*
        //Function to generate a unique value for use as a session key.
        //generate session id
*/
void generate_unique_key(char *session_id, size_t length);

/*

*/
char* generate_unique_id();

/*
        //get timestamp
*/
void get_timestamp(char *buffer, size_t size);

//      [STRING]

/*
        //space removal function
*/
void trim_whitespace(char *str);

/*
        //read inf fuction
*/
char *get_value_from_inf(const char *filename, const char *target_section, const char *target_key);

//      [config]
/*
        // read config
*/
int read_server_config(const char *section, char *ip_buffer, size_t ip_buffer_size, int *port);


/*
	//
*/
void  getpamconf(struct st_pam_conf * pam_conf);

//      [network]
/*
        //
        //socket connection function
*/
int connect_to_server(int *sock, const char *section);

/*
        // data transfer function
*/
int send_data(int sock, const char *data);

/*
        //data reception function
*/
int receive_data(int sock, char *buffer, size_t buffer_size);

/*
        //
*/
int check_server_connection(const char *ip, int port);

//      [user item]
/*
        // get encrypted password
*/
const char* get_encrypted_password_from_shadow_v2(const char* username);

/*
        // get encrypted password
        // This is a function that retrieves a specific user's password hash from the /etc/shadow file.
*/
const char* get_encrypted_password_from_shadow(const char* user);

/*
	//JSON . json-c
*/
char *create_pam_archivelogdate_using_JSON(struct _archive_log logitem);

/*
        //JSON . json-c
*/
char *create_pamlogdata_using_JSON(const char * agtauth_no, const char * agtId, const char* action_type, const char* session_status, const char* account, const char* ipaddr, const char* session_key, const char* message);

/*
        //JSON . jsnon-c
*/
char *create_sessionlogdata_using_JSON(const char * agtauth_no, const char * agtId,  const char* prefix, const char* session_id, const char* account, int uid, int gid, int isconsole, const char* ipaddr, long ltime, const char* session_key);

/*
        //JSON . json-c
*/
char *create_sulogdata_using_JSON(const char * agtauth_no, const char * agtId, const char* account, const char* switch_account, const char* su_command, const char* client_ip, long time, const char* session_key);

/*
        //
*/
void initializeStorageBuffer();

/*
        //
*/
int addStringtoStorageBuffer(const char* str);

/*
        //
*/
char* getFinalStorageBuffer();

/*
        //
*/
void freeStorageBuffer();

/*
	//
*/
int sending_data_to_logger(char * sAgentId, unsigned char iType, unsigned char iCode,/* unsigned char iVerMaj,*/char* iVer, char * data);

/*
	//
*/
int initializeAuthVariables(void);

/*
	//
*/
char *getAgentId();

/*
	//
*/
void setAgentId(char * id);

/*
	//
*/
void parse_json(const char *filename);

#ifdef _OLD_SRC
/*
	//
*/
void parse_pam_policy(const char *filename);
#endif //_OLD_SRC

/*
	//
*/
PamPolicy parsePamPolicy(const char *filename);
void freePamPolicy(PamPolicy *pamPolicy);

/*
	//
*/
//int isPamPolicyMatched(const PamPolicy *pamPolicy, const char *ipaddr, const char *account);
Rule *isPamPolicyMatched(const PamPolicy *pamPolicy, const char *ipaddr, const char *account);

/*
	//
*/
int isSuPamPolicyMatched(const PamPolicy *pamPolicy, const char *ipaddr, const char *account, const char *switch_account);

/*
	//
*/
void get_local_ip(char *ip_buffer, size_t buffer_size);

/*
	//
*/
void parse_ssh_connection(pam_handle_t *pamh, bool isConsole );

const char * getPamRuleFilePath(const char* sDataHomeDir);

const char * getPambakSulogFilePath(const char* sDataHomeDir);

const char * getPambakSessionlogFilePath(const char* sDataHomeDir);

const char * getPambaklogFilePath(const char* sDataHomeDir);

const char * getPamConfFilePath(const char * sDataHomeDir);

const char * getPamLogFilePath(void);

int is_valid_ip(const char *ip);

//void get_env_vars(pid_t pid);
char* get_env_var(pid_t pid, const char* var_name);
void print_env_vars(pid_t pid);

char* read_env_variable(pid_t pid, const char* var_name) ;

pid_t get_tty_pid(const char *tty_name);

char* resolve_actual_tty(pid_t pid);

//
char *generate_uuid();

int get_shell_from_pam(pam_handle_t *pamh, char **shell);

bool is_pam_user_ndshell(pam_handle_t *pamh);

int get_agent_id(const char *filename);

const char *get_value_as_string(const char *json_file, const char *key);

int check_pam_policy(const char *json_file, const char *ip, const char *account, int *pri_no, char **agt_auth_no, int *action, int *logging);
//int check_pam_policy(const char *json_file, const char *ip, const char *account, int *pri_no, char **agt_auth_no);

int check_sam_policy(const char *json_file, const char *ip, const char *account, int *pri_no, char **agt_auth_no);
#ifdef _OLD_SRC_
struct _archive_log* create_archive_log(
    const char *prefix,
    const char *agentId,
    const char *agtAuthNo,
    const char *sessionKey,
    const char *time,
    const char *connect_type,
    const char *sourceIp,
    const char *last_auth_type,
//    const char *secur_step_no,
    const char *sys_account,
    const char *hiware_account,
    const char *switch_sys_account,
    const char *message,
    const char * result,
    const char *certTpCode,
            const char *certAppTpCode,
            const char *certSucesFailYn,
            const char *certStepSeqNo

) ;
#else // _OLD_SRC_

struct _archive_log* create_archive_log		(

	const char *svrConnStartTime,
	const char *svrConnEndTime,
	const char *svrConnRstTpCode,
	const char *svrConnFailRsnCode,
	const char *agtNo,
	const char *agtConnFormTpCode,
	const char *agtAuthNo,
	const char *portNo,
	const char *userIp,
	const char *securStepNo,
	const char *svrConnSessKey,
	const char *connAcctId,
	const char *switchAcctId,
	const char *pamAgtAuthNo,
	const char *userNo,
	const char *pamCertDtlCode,
	const char *pamCertDtlAuthCode,

	const char *certTpCode,
        const char *certAppTpCode,
        const char *certSucesFailYn,
        const char *certStepSeqNo
) ;


#endif //_OLD_SRC_

int is_ip_in_range(const char *ip, const char *range);

int is_account_in_list(const char *account, struct json_object *account_list);

int is_time_in_range(const char *start, const char *end, time_t current_time);

int is_wday_time_valid(const struct json_object *wday_list, int current_wday, time_t current_time);

int validate_json_sampolicy(const char *json_file, const char *ip, const char *account, time_t current_time, int current_wday, char **agtAuthNo,int *action, int *logging);

int validate_json_sampolicy_without_date(const char *json_file, const char *ip, const char *account, char **agtAuthNo,int *action, int *logging);

int validate_json_exceptionConnection(const char *json_file, const char *ip );

int check_su_session(pam_handle_t *pamh);

// Function to initialize session info
SessionInfo *init_session_info();

// Function to free session info
void free_session_info(SessionInfo *info);

// Utility function to retrieve PAM items
char *get_pam_item_str(pam_handle_t *pamh, int item_type);

// Function to collect console session info
SessionInfo *get_console_session_info(pam_handle_t *pamh);

// Function to collect SSH session info
SessionInfo *get_ssh_session_info(pam_handle_t *pamh);

// Function to collect su session info
SessionInfo *get_su_session_info(pam_handle_t *pamh);

int get_ssh_port();

int get_ssh_listening_port_from_cmd() ;

int get_current_ssh_port(pam_handle_t *pamh);

int get_ssh_port(pam_handle_t *pamh) ;

// Function declaration
char* read_config_value(const char* filename, const char* section, const char* key);

// Function to get environment variable (PAM or global)
const char* get_env_variable(pam_handle_t *pamh, const char *key);
 
#endif // ND_UTILS_H
