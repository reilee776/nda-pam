
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include "common.h"
#include <errno.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/time.h> 
#include <sys/file.h>
#include <uuid/uuid.h>
#include "./libsrc/nd_utils.h"
#include "./libsrc/nd_nix_logs.h"
#include "./libsrc/nd_restapi_func.h"
#include <json-c/json.h>
#include <curl/curl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <dlfcn.h> 

/*
////////////
*/
typedef RSA *(*RSA_NEW_FUNC)(void);
typedef BIGNUM *(*BN_NEW_FUNC)(void);
typedef int (*RSA_GEN_FUNC)(RSA *, int, BIGNUM *, void *);
typedef void (*RSA_FREE_FUNC)(RSA *);
typedef void (*BN_FREE_FUNC)(BIGNUM *);
typedef int (*PEM_WRITE_BIO_PRIV_FUNC)(BIO *, RSA *);

#define RSA_KEY_BITS 2048

int g_nFailCnt = 0;
//void nd_pam_log(int level, char* filename, int line, const char *fmt, ...);

char * g_sDataIssueKey;
char * g_sDataRandomKey;
char * g_sDataAuthKey;
char * g_sDataSecretKey;
char * g_sUserNumber;

char * g_sDataUserLoginResult;
char * g_sDataTemporaryAccessKey;

//char * g_DataRandomUrl;

char * g_sDataSysID;
char * g_sDataSysPW;

char g_sDataRandomUrl[MAX_URL_LEN];
char g_sDataUserLoginUrl[MAX_URL_LEN];
char g_sDataSystemLoginUrl[MAX_URL_LEN];
char g_sDataTwoFactLoginIrl[MAX_URL_LEN];

char * g_sConfFilePath;

char g_sDataAgentId[2];


//static const char *current_user;

pthread_mutex_t session_id_mutex;


//nd_pam_sulog
#define nd_sulog(level, fmt, ...) nd_pam_sulog(level, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__)

char g_sAccount[256];
char g_szLoginUserOrgName[1024];
char g_szHiwareAccount[256];

#define ESC "\033"
#define MAX_ATTEMPTS 3

bool g_isLogin = false;

int authentication_failed = 0;

struct st_hiauth_item nd_hiauth_item[] = {
        {HIAUTH_ID, "Hiware User: "},
        {HIAUTH_PW, "Hiware Password: "},
};

struct st_log_level nd_log_level[] = {
        {NDLOG_INF, "INF"},
        {NDLOG_WAN,"WAN"},
        {NDLOG_DBG,"DBG"},
        {NDLOG_TRC,"TRC"},
        {NDLOG_ERR,"ERR"},
};

struct st_sesslog_type nd_slog_type[] ={
        {NDSLOG_LOGIN, "NDLOGIN"} ,
        {NDSLOG_LOGOFF, "NDLOGOFF"},
};

/*
	//It is an optional parameter that is a function pointer used for cleaning up the data. 
	//It is called when the PAM session ends.
*/
static void cleanup_func (pam_handle_t *pamh, void *data, int error_status) 	{
	(void)pamh;         // Mark pamh as unused
    	(void)error_status; // Mark error_status as unused

	free(data);
}

/*
	//Banner image displayed upon successful authentication.
*/
void print_nd_banner (void)
{
	printf ("\n\n");
        printf ("\x1b[31m     NNNN              NNNN  DDDDDDDDDDDDDDDDD                       \033[0m\n");
        printf ("\x1b[32m     NNNN  NNNN        NNNN                  DDDDD   nn    nn  eeeeeee  tttttttt     a      nn    nn   ddddddd   \033[0m\n");
        printf ("\x1b[33m     NNNN   NNNN       NNNN                  DDDDD   nnn   nn  ee          tt       aaa     nnn   nn   dd    dd  \033[0m\n");
        printf ("\x1b[34m     NNNN    NNNN      NNNN                  DDDDD   nnnn  nn  ee          tt      aa aa    nnnn  nn   dd     dd \033[0m\n");
        printf ("     NNNN     NNNN     NNNN                  DDDDD   nn nn nn  eeeeeee     tt     aa   aa   nn nn nn   dd     dd \033[0m\n");
        printf ("     NNNN      NNNN    NNNN                  DDDDD   nn  nnnn  ee          tt    aaaaa  aa  nn  nnnn   dd     dd \n");
        printf ("     NNNN       NNNN   NNNN                  DDDDD   nn   nnn  ee          tt    aaaaaa aa  nn   nnn   dd    dd  \n");
        printf ("     NNNNNNNNN   NNNN  NNNN                  DDDDD   nn    nn  eeeeeee     tt    aa     aa  nn    nn   ddddddd   \n");
        printf ("     NNNNNNNNNNN    NNNNNNN  DDDDDDDDDDDDDDDDDD                      \n");
        printf ("     NNNN             NNNNN  DDDDDDDDDDDDDDD                 \n");

        printf ("\n\n");

}

/*
	//Banner image displayed upon successful authentication. TEMP
*/
void print_nd_banner_type2 (void)
{
        printf ("\n\n");
	printf ("::::::::::::::::::::::::::::::::::::::::::: #\tWelcome to the Secure Login System! \n");
        printf (":::::       ::::::::::             :::::::: \n");
        printf (":::::    :   :::::::::    :::::::   ::::::: #\tHello, and welcome to Netand's secure environment. \n");
        printf (":::::    ::    :::::::    :::::::::   ::::: #\tPlease be mindful of your security at all times as you access this system.  \n");
        printf (":::::    ::::   ::::::    ::::::::::   :::: #\tWe strive to maintain the highest levels of protection for your data and privacy. \n");
        printf (":::::    :::::   :::::    ::::::::::   :::: \n");
        printf (":::::    ::::::   ::::    ::::::::::   :::: \n");
        printf (":::::    :::::::   :::    ::::::::::   :::: \n");
        printf (":::::       .::::   ::    ::::::::::   :::: \n");
        printf (":::::         ::::        :::::::::   ::::: \n");
        printf (":::::           ::::      ::::::::   :::::: \n");
        printf (":::::    ::::::::::::               ::::::: \n");
	printf ("::::::::::::::::::::::::::::::::::::::::::: \n");
        printf ("\n\n");

}

/*
	//Welcome message displayed upon successful authentication.
*/
void print_nd_warnning_msg (void)
{
	printf("#\tWelcome to the Secure Login System!\n");
        printf("#\n");
        printf("#\tHello, and welcome to Netand's secure environment. \n");
        printf("#\tPlease be mindful of your security at all times as you access this system. \n");
        printf("#\tWe strive to maintain the highest levels of protection for your data and privacy.\n");
        printf("#\n");
        printf("#\tThis is a secure login system designed to protect your credentials and sensitive information. \n");
        printf("#\tUnauthorized access is strictly prohibited, and all activities are logged and monitored for your safety.\n");
        printf("#\tPlease ensure that you are accessing this system for authorized purposes only. \n");
        printf("#\tMisuse of this system could result in severe penalties, including suspension of access.\n");
        printf("#\n");
        printf("#\t\x1b[31m⚠️ Attention: Network security is our top priority. Any suspicious activity will be flagged and reported to the \033[0m\n#\t\x1b[31mappropriate authorities.\033[0m\n");
        printf ("#\n");
        printf("#\tRemember, safeguarding your login credentials is your responsibility. Always keep them private and secure.\n");

        printf("#\tThank you for choosing Netand. Stay vigilant and proceed with caution. Secure your connection and have a \n#\tproductive session!\n\n");

}

/*
	//Function to retrieve the failure count stored locally.
*/
int read_fail_count(const char *username) 	{

	FILE *file = fopen(COUNTER_FILE, "r");
	if (!file) {
		return 0; 
	}

	char line[256];
	while (fgets(line, sizeof(line), file)) {
		char user[256];
		int count;
		sscanf(line, "%s %d", user, &count);
		if (strcmp(user, username) == 0) {
			fclose(file);
		    	return count;
		}
	}
	fclose(file);
	return 0; 
}

/*
	//Function to retrieve the failure count stored locally.
*/
void increment_fail_count(const char *username) 	{

	FILE *file = fopen(COUNTER_FILE, "r+");
	if (!file) {
		return; 
	}

	char line[256];
	int found = 0;
	int count = 0;

	while (fgets(line, sizeof(line), file)) {
		char user[256];
		sscanf(line, "%s %d", user, &count);
		if (strcmp(user, username) == 0) {
			found = 1;
		    	count++; 
		    	break;
		}
	}

	rewind(file);

	if (found) {
		fprintf(file, "%s %d\n", username, count);
	} else {
		fprintf(file, "%s %d\n", username, 1); 
	}

	fclose(file);
}

/*
	//"Function to reset the authentication failure count.
*/
void reset_fail_count(const char *username) 	{

	FILE *file = fopen(COUNTER_FILE, "r");
	if (!file) {
		return; 
	}

	char temp_file[] = "/tmp/pam_fail_count.tmp";
	FILE *temp = fopen(temp_file, "w");
	char line[256];


	while (fgets(line, sizeof(line), file)) {
		char user[256];
		int count;
		sscanf(line, "%s %d", user, &count);
		if (strcmp(user, username) != 0) {
			fprintf(temp, "%s %d\n", user, count);
		}
	}

	fclose(file);
	fclose(temp);


	rename(temp_file, COUNTER_FILE);
}

int read_pam_config(const char *filename, pam_config *config) {

	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		perror("Failed to open file");
		return -1; // 파일 열기 실패
	}

	char line[MAX_LINE_LENGTH];
	while (fgets(line, sizeof(line), file) != NULL) {
		// 줄 끝의 개행 문자 제거
		line[strcspn(line, "\n")] = 0;

		// 키-값 분리
		char *key = strtok(line, "=");
		char *value = strtok(NULL, "=");

		// PAM_MODE 설정
		if (key && value) {
		    if (strcmp(key, "PAM_MODE") == 0) {
			strncpy(config->pam_mode, value, sizeof(config->pam_mode) - 1);
			config->pam_mode[sizeof(config->pam_mode) - 1] = '\0'; // null-terminate
		    } else if (strcmp(key, "PAM_SU_CONTROL") == 0) {
			strncpy(config->pam_su_control, value, sizeof(config->pam_su_control) - 1);
			config->pam_su_control[sizeof(config->pam_su_control) - 1] = '\0'; // null-terminate
		    }
		}
	}

	fclose(file);
	return 0; // 성공적으로 읽음
}

/*
	//get user information
*/
void get_user_info(struct pam_user_info *user_info,  pam_handle_t *pamh) {

	char *crypted;
	const char *input_passwd;
	//const char *encrypted_passwd;
	const char *current_user;
	const char *switch_user;
	//struct st_auth_result_data  ret_data;
	struct st_hiauth_su_login_result su_login_ret;
	struct st_hiauth_su_access_perm_result su_access_perm;
	bool bJumpPwd = false;
	bool bIsSuFailed = false;
    	int retval = 0;
	
	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
        if (sDataHomeDir == NULL)
                sDataHomeDir = strdup(PRODUCT_NM);

	if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	nd_log (NDLOG_INF, "====================================================================");
	nd_log (NDLOG_INF, "[get pam session user information]");
	nd_log (NDLOG_INF, "--------------------------------------------------------------------");

	char * authsvr_emergency_act = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,PAM_AUTHSVR_EMERGENCY_ACTION);  // PAM_AUTHSVR_EMERGENCY_ACTION

	if (user_info == NULL || pamh == NULL) {

		nd_log (NDLOG_ERR, "The input parameter information of the function is not valid.");
		return;
	}

	/*
		// Retrieving the current service name from PAM (Pluggable Authentication Module).
		//service
	*/
	retval = pam_get_item(pamh, PAM_SERVICE, (const void**)&user_info->service);
	if (retval != PAM_SUCCESS && !user_info->service)	{
		nd_log (LOG_LEVEL_ERR, "[PREFIX-ERR CODE] Failed to retrieve the service name related to the PAM session.");
	}

	nd_log (NDLOG_INF, "\t- service name      :%s", user_info->service);

	
	if (strcmp (user_info->service , STR_SU) == 0 || strcmp (user_info->service, STR_SUL) == 0 )
	{
		nd_log (NDLOG_INF, "\t- session type      :su");
		if (pam_get_user(pamh, &switch_user, NULL) == PAM_SUCCESS && switch_user != NULL)      {

			strncpy (user_info->switchusernname, switch_user ? switch_user : "unknown-user", sizeof(user_info->switchusernname) - 1 );
            		user_info->switchusernname[sizeof(user_info->switchusernname) - 1] = '\0';

			strncpy (user_info->switchuserActualNm, getenv(ND_HIWARE_ACTUALNM_KEY) ? getenv(ND_HIWARE_ACTUALNM_KEY) : "", sizeof (user_info->switchuserActualNm) );
        	}

		nd_log (NDLOG_INF, "\t- switchusernname   :%s", user_info->switchusernname);

		/*
			// Reading the name of the currently logged-in user set in the environment variable.
		*/
		const char *envuser = NULL;
		current_user= getenv("USER");
		sprintf (user_info->username, envuser ? current_user: "unknow user");
		user_info->bNeedtoEnvUpdata = false;

		retval = requestSuAuthToApiServer(user_info->username, user_info->realpwd, &su_login_ret);
		if (retval !=  HI_AUTH_RET_SUCCEED)
		{
			user_info->switch_allow = PAM_SWITCH_DENY;
			user_info->login_status = 1;
			bIsSuFailed = true;
			return;
		}
		
		retval = requestSuAccessPermissionsToApiServer(user_info->username, user_info->switchusernname, &su_access_perm );
		if (retval == HI_AUTH_RET_SUCCEED)
		{
			user_info->bNeedtoEnvUpdata = true;
			user_info->switch_allow = PAM_SWITCH_ALLOW;
			user_info->login_status = 0;
			bJumpPwd = true;

			goto password_next;
		}
		else
		{
			if (strcmp (authsvr_emergency_act, SET_MODE_BYPASS) == 0 )
			{
				goto password_next;
			}

			user_info->switch_allow = PAM_SWITCH_DENY;
			user_info->login_status = 1;
			bIsSuFailed = true;
			return;
		}
	}
	else
	{
		if (pam_get_user(pamh, &current_user, NULL) == PAM_SUCCESS && current_user != NULL)      {

			strncpy(user_info->username, current_user, sizeof(user_info->username) - 1);
			user_info->username[sizeof(user_info->username) - 1] = '\0';
		}

		nd_log (NDLOG_INF, "\t- current_user      :%s", user_info->username);
	}

	/*
		// Getting the user input password.
	*/
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &input_passwd, NULL);
	if (retval != PAM_SUCCESS) {

		nd_log(NDLOG_ERR,"failed to get user password...");
		return;
	}

	strncpy (user_info->realpwd, input_passwd, sizeof (user_info->realpwd));
password_next:

	/*
		//Determining the login type of the current session (distinguishing between console login and terminal login).
	*/
	user_info->isConsole = false;
	pam_get_item(pamh, PAM_TTY, (const void **)&user_info->tty);
	if (user_info->tty)        {

		if (strncmp(user_info->tty, "tty", 3) == 0 )       {
				user_info->isConsole = true;
		}
	} 

	nd_log (NDLOG_INF, "\t- is console        :%d", user_info->isConsole);

	/*
		//Receives a username and returns the corresponding user's password hash.
	*/
	user_info->encrypted_password = get_encrypted_password_from_shadow(current_user);
	if (!user_info->encrypted_password )	{
		return;
	}

	nd_log (NDLOG_INF, "\t- user enc pwd      :%s", user_info->encrypted_password);

	/*
		//Calls the crypt function using the user input password (input_passwd) along with the user's password hash (user_info->encrypted_password).
	*/
	if (bJumpPwd == false)
	{
		crypted = crypt(input_passwd, user_info->encrypted_password);
		if (strcmp(crypted, user_info->encrypted_password) == 0) 	{

			user_info->login_status = 0;
		} else 		{

			user_info->login_status = 1;
		}
	}
	else
	{
		if (!bIsSuFailed)
		 	user_info->login_status = 0;
	}

	/*
		// Getting the UID and GID
	*/
	struct passwd *pw = getpwnam(user_info->username);
	if (pw != NULL) 	{

		user_info->uid = pw->pw_uid;
		user_info->gid = pw->pw_gid;
		strncpy(user_info->home_directory, pw->pw_dir, sizeof(user_info->home_directory) - 1);
		user_info->home_directory[sizeof(user_info->home_directory) - 1] = '\0';
		strncpy(user_info->shell, pw->pw_shell, sizeof(user_info->shell) - 1);
		user_info->shell[sizeof(user_info->shell) - 1] = '\0';
	}

	/*
	nd_log (NDLOG_INF, "\t- user uid          :%d", user_info->uid);
	nd_log (NDLOG_INF, "\t- user gid          :%d", user_info->gid);
	*/

	/*
		// Authentication Method (ex: password)
	*/
	strncpy(user_info->auth_method, "password", sizeof(user_info->auth_method) - 1);
	user_info->auth_method[sizeof(user_info->auth_method) - 1] = '\0';

	/*
		// The IP address cannot be retrieved directly in the PAM environment.
	*/
	if (user_info->isConsole == false )        {
        	retval = pam_get_item(pamh, PAM_RHOST, (const void **)&user_info->ip_address);
		if (retval != PAM_SUCCESS && !user_info->ip_address) 	{
			// need to log message
		} 
    	}

	/*
		// login time
	*/
	user_info->login_time = time(NULL);
	nd_log (NDLOG_INF, "\t- user login time   :%d", user_info->login_time);

	/*
		// session ID (ex: Generate UUID or Unique Session ID)
	*/
	strncpy(user_info->session_id, "session1234", sizeof(user_info->session_id) - 1);
	user_info->session_id[sizeof(user_info->session_id) - 1] = '\0';

	/*
		// Authentication Failure count (initial value)
	*/
	user_info->auth_fail_count = 0; // initial value

	/*
		// Additional Authentication Information
	*/
	strncpy(user_info->mfa_info, "none", sizeof(user_info->mfa_info) - 1);
	user_info->mfa_info[sizeof(user_info->mfa_info) - 1] = '\0';

	nd_log (NDLOG_INF, "--------------------------------------------------------------------");
}

int set_pam_data(pam_handle_t *pamh, const char *data_name, const char *data_value, 
                 void (*cleanup_func)(pam_handle_t *pamh, void *data, int error_status)) {

	if (pamh == NULL || data_name == NULL || data_value == NULL) 	{

		return PAM_BUF_ERR; 
	}

	char *data_copy = strdup(data_value);	// strdup performs a similar role to malloc by allocating memory and copying the string
	if (data_copy == NULL) 		{

		return PAM_BUF_ERR;
	}

	int retval = pam_set_data(pamh, data_name, data_copy, cleanup_func);
	if (retval != PAM_SUCCESS) 	{

		free(data_copy); 
	}

	return retval;
}

int get_pam_data(pam_handle_t *pamh, const char *data_name, const void **data_out) 	{

	if (pamh == NULL || data_name == NULL || data_out == NULL) 	{

		return PAM_BUF_ERR; 
	}

	int retval = pam_get_data(pamh, data_name, data_out);
	if (retval != PAM_SUCCESS) 	{

		*data_out = NULL; 
	}

	return retval;
}

/*
	//su control get  who commond output data
*/
pam_client_info  get_su_master_info (pam_handle_t *pamh)
{
	const char      *tty;
	//bool bFinded 	= false;
	bool found 	= false;
	int retval 	= 0;
	pam_client_info clientInfo;
	const char *ssh_connection = getenv("SSH_CONNECTION");

	strcpy(clientInfo.ip, NONE_STRING);
    	strcpy(clientInfo.port, NONE_STRING);
    	strcpy(clientInfo.tty, NONE_STRING);

	if (ssh_connection) {

		// SSH_CONNECTION format: "client_ip client_port server_ip server_port"
		char *token = strtok((char *)ssh_connection, " ");
		if (token != NULL) 		{

			strncpy(clientInfo.ip, token, INET_ADDRSTRLEN); 
			clientInfo.ip[INET_ADDRSTRLEN - 1] = '\0'; // null-terminate
			token = strtok(NULL, " ");

			if (token != NULL) 		{
				strncpy(clientInfo.port, token, sizeof(clientInfo.port)); 
				clientInfo.port[sizeof(clientInfo.port) - 1] = '\0'; 
			}
		}
		found = true;
	} else 		{

		retval = pam_get_item(pamh, PAM_TTY, (const void **)&tty);
		if (retval == PAM_SUCCESS) 
		{
			strncpy(clientInfo.tty, tty, sizeof(clientInfo.tty));
			clientInfo.tty[sizeof(clientInfo.tty) - 1] = '\0'; 

		    	FILE *fp = popen("who", "r");
		    	if (fp != NULL) 
			{
				char buffer[256];
				while (fgets(buffer, sizeof(buffer), fp) != NULL) 
				{
			    		strtok(buffer, " ");
			    		char *tty1 = strtok(NULL, " ");
			    		strtok(NULL, " ");
			    		strtok(NULL, " ");
			    		char *ip = strtok(NULL, " ");

			    		if (ip != NULL && ip[0] == '(') 
					{
						ip++;
						char *end = strchr(ip, ')');
						if (end != NULL) 	{
				    			*end = '\0';
						}
			    		}	

			    		if (strcmp(tty1, clientInfo.tty) == 0) {

						strncpy(clientInfo.ip, ip, INET_ADDRSTRLEN);
						clientInfo.ip[INET_ADDRSTRLEN - 1] = '\0'; 
						found = true;
						break;
			    		}

				}

				pclose(fp);
		    	}
		}
	}

	if (!found) 	{

		strcpy(clientInfo.ip, NONE_STRING);
		strcpy(clientInfo.port, NONE_STRING);
	}

	return clientInfo;
}


/*
	//
*/
struct st_hiauth_input_data * OperateHiAuth(pam_handle_t * pamh)
{
	int retval = 0, style = PAM_PROMPT_ECHO_ON;
	char * pHiAuthData = NULL;
	struct st_hiauth_input_data *input_data = malloc(sizeof(struct st_hiauth_input_data));

	if (input_data == NULL) 	{

        	return NULL;
    	}


	for (int i = 0 ; i < HIAUTH_MAX ; i ++ )
	{
		if(nd_hiauth_item[i].index == HIAUTH_PW)
			style = PAM_PROMPT_ECHO_OFF;
		else
			style = PAM_PROMPT_ECHO_ON;

		retval = pam_prompt(pamh, style, &pHiAuthData, nd_hiauth_item[i].item);
		if (retval == PAM_SUCCESS && pHiAuthData)      {
			
			if ( nd_hiauth_item[i].index == HIAUTH_ID)
				snprintf (input_data->sHiAuthId, sizeof (input_data->sHiAuthId), pHiAuthData);
			else if (nd_hiauth_item[i].index == HIAUTH_PW)
				snprintf (input_data->sHiAuthPw, sizeof (input_data->sHiAuthPw), pHiAuthData);
			else	{
			}
			
		}

		free (pHiAuthData);
	}

	return input_data;
}


/*
	// 
*/
int check_session_type( pam_handle_t * pamh, const char *tty, const char *service)
{
	// Validate inputs
	if (tty == NULL) {
		fprintf(stderr, "[ERR] TTY is NULL\n");
		return -2;
	}

	if (service == NULL) {
		fprintf(stderr, "[ERR] Service is NULL\n");
		return -3;
	}

	// Determine session type based on TTY
	if (strncmp(tty, "tty", 3) == 0) {
		return AUTH_PURPOS_CONSOLE;
	} else if (strncmp(tty, "/pts/", 5) == 0) {
		return AUTH_PURPOS_TERMINAL;
	}

	// Determine session type based on service
	if (strcmp(service, STR_SU) == 0 || strcmp(service, STR_SUL) == 0) {
		return AUTH_PURPOS_SU;
	}

	// Default case
	fprintf(stderr, "[ERR] Unable to determine session type\n");
	return -1;	
}


int nd_pam_authenticate_user (char * uuid_str, struct pam_user_info user_info, pam_handle_t * pamh)
{
	int authsvr_port = 0;
	int retval = 0;

	char  	*hiwareTwoFactData = NULL;
	char 	sTwoFactString[128];
	char    sDataEnv_var[MAX_ENV_STR_LEN];
	char 	szErrMsg[1024] = {0,};

	char    sDataLastLoginStatus[ND_LASTAUTHTYPE_MAX_LEN] = {0,};	

	sprintf (sTwoFactString, "OTP(One-Time Password): ");

	struct _archive_log 				*logitem;
	struct st_hiauth_input_data    			*hiauth_input_data;
	st_hiauth_twofact_login_result			hi_twofact_ret;
	struct st_hiauth_hiware_login_result 	hi_hiwareauth_ret;

	struct _msg_header_   header = {
        	.iMsgVer        = 0,
        	.iMsgTotalSize  = 0
	};

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
		sDataHomeDir = strdup(PRODUCT_NM);

	//const char * sSettingFile = getPamConfFilePath (sDataHomeDir);
	if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	/*
		// Retrieve the server connection information from the configuration file.
	*/
	char * auth_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERIP);
    	char * auth_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERPORT); 
	char * authsvr_emergency_act = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,PAM_AUTHSVR_EMERGENCY_ACTION);

	nd_log (NDLOG_INF, "auth_server_ip GET VALUE [%s]", auth_server_ip);

	/*
		// convert server port
	*/
	if (auth_server_port)		{
		authsvr_port = atoi (auth_server_port);
	}else				{
		authsvr_port = PAM_HIAUTH_DEFAULT_PORT;
	}

	/*
		// server connect check
	*/
	bool bisAlive_server = check_server_connection(auth_server_ip, authsvr_port);
	if (bisAlive_server != true )
	{
		for (int i = 0 ; i < 3; i++ )
		{
			bisAlive_server = check_server_connection(auth_server_ip, authsvr_port);
			if (bisAlive_server)	{
				sleep(3);
				break;
			}
		}
	}

	/*
		// Exception Handling Based on Configuration Settings
	*/
	if (bisAlive_server != true)
	{
		if (strcmp (authsvr_emergency_act, SET_MODE_BYPASS) == 0 )	{

			return PAM_SUCCESS;
		}
		else if (strcmp (authsvr_emergency_act, SET_MODE_BLOCK) == 0 )	{
			return PAM_AUTH_ERR;
		}
		else								{
			return PAM_SUCCESS;
		}	
	}

	int pri_no, action, logging;
    	char *agt_auth_no;

	char *agent_id = get_value_as_string(getPamRuleFilePath( sDataHomeDir), "agentId");
	
	syslog (LOG_ERR, "check_pam_policy : ip addr (%s), account (%s)", user_info.ip_address, user_info.username);
	syslog (LOG_ERR, "RULE PATH :%s", getPamRuleFilePath( sDataHomeDir));

	syslog (LOG_ERR, "agent_id = %s\n", agent_id ? agent_id : "NULL");

	if (check_pam_policy (getPamRuleFilePath( sDataHomeDir), user_info.ip_address, user_info.username, &pri_no, &agt_auth_no, &action, &logging))
	{

		syslog (LOG_ERR,">>>>>> check_pam_policy : agt_auth_no :(%s), pri_no (%d), action (%d), logging(%d)", agt_auth_no, pri_no, action, logging);
		if (action == PAM_USER_RULE_ACT_DENY)
		{
			header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                	header.iMsgCode = PACK_MSG_CODE_REJECT_PASSWD;

			logitem =  create_archive_log ("NDAPAM-LOGIN", agent_id, agt_auth_no, uuid_str, "", (user_info.isConsole == true)? "console" : "terminal", user_info.ip_address, "NDAPAM-OS-AUTH",  user_info.username, "", "", "Permission denied", false);

			/*
			snprintf (logitem.prefix, 	ND_PREFIX_MAX_LEN,	 "NDAPAM-LOGIN");
			logitem.prefix[ND_PREFIX_MAX_LEN - 1] = '\0';
			snprintf (logitem.agentId,      ND_AGENTID_MAX_LEN,	 "%s",agent_id);
			snprintf (logitem.agtAuthNo, 	ND_AGTAUTHNO_MAX_LEN,	 (char*)agt_auth_no);
			snprintf (logitem.sessionKey, 	ND_UUID_LENGTH,		 uuid_str);
			snprintf (logitem.connect_type, ND_CONNECTTYPE_MAX_LEN,  (user_info.isConsole == true)? "console" : "terminal");
			snprintf (logitem.sourceIp, 	ND_SOURCEIP_MAX_LEN,	 user_info.ip_address);
			snprintf (logitem.last_auth_type, ND_LASTAUTHTYPE_MAX_LEN,	 "NDAPAM-OS-AUTH");
			snprintf (logitem.sys_account, 	ND_SYSACCOUNT_MAX_LEN,	 user_info.username);
			snprintf (logitem.message, 	ND_LOGMSG_MAX_LEN,	"Permission denied");
			logitem.result = false;
			*/
			
			nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);

			free_archive_log(logitem);

			free ((void*)agent_id);
			free ((void*)agt_auth_no);

			return PAM_PERM_DENIED; 
		}
		//HIWARE_AGTAUTHNO_KEY_FORMAT

		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_AGTAUTHNO_KEY_FORMAT, agt_auth_no);
        	pam_putenv(pamh, sDataEnv_var);

		sprintf (user_info.agtAuthNo, "%s", agt_auth_no);
	}
	else
	{
		syslog (LOG_ERR, "No matching rule found for IP: %s and Account: %s\n", user_info.ip_address, user_info.username);
		header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
		header.iMsgCode = PACK_MSG_CODE_REJECT_PASSWD;

		logitem =  create_archive_log ("NDAPAM-LOGIN", agent_id, agt_auth_no, uuid_str, "", (user_info.isConsole == true)? "console" : "terminal", user_info.ip_address, "NDAPAM-OS-AUTH",  user_info.username, "", "", "Authentication failed", false);
		/*

		snprintf (logitem.prefix,  	ND_PREFIX_MAX_LEN ,     "NDAPAM-LOGIN");
		logitem.prefix[ND_PREFIX_MAX_LEN - 1] = '\0';
		snprintf (logitem.agentId, 	ND_PREFIX_MAX_LEN,      agent_id);
		snprintf (logitem.agtAuthNo, 	ND_AGTAUTHNO_MAX_LEN,   "%s", "");
		snprintf (logitem.sessionKey, 	ND_UUID_LENGTH,   	uuid_str);
		snprintf (logitem.connect_type, ND_CONNECTTYPE_MAX_LEN, (user_info.isConsole == true)? "console" : "terminal");
		snprintf (logitem.sourceIp,    	ND_SOURCEIP_MAX_LEN,  	user_info.ip_address);
		snprintf (logitem.last_auth_type, ND_LASTAUTHTYPE_MAX_LEN, "NDAPAM-OS-AUTH");
		snprintf (logitem.sys_account,  ND_SYSACCOUNT_MAX_LEN, 	user_info.username);
		snprintf (logitem.message,  	ND_LOGMSG_MAX_LEN,     	"Authentication failed");
		logitem.result = false;
		*/

		nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);

		free_archive_log(logitem);

		free ((void*)agent_id);
                free ((void*)agt_auth_no);
	
		return PAM_PERM_DENIED;

	}

    	// 메모리 해제`:wq
    	//freePamPolicy(&pamPolicy);

	hiauth_input_data = OperateHiAuth(pamh);
	if ((hiauth_input_data->sHiAuthId == NULL || strlen (hiauth_input_data->sHiAuthPw) <= 0)  ||
		(hiauth_input_data->sHiAuthPw == NULL || strlen (hiauth_input_data->sHiAuthPw) <= 0))
	{
		nd_log (LOG_LEVEL_ERR, "HIWARE user authentication information is missing, causing the authentication task to fail");
		free ((void*)agent_id);
                free ((void*)agt_auth_no);
		return PAM_AUTH_ERR;
	}

	nd_log (NDLOG_INF, "====================================================================");
    	nd_log (NDLOG_INF, "[INPUT HIWARE user information]");
    	nd_log (NDLOG_INF, "--------------------------------------------------------------------");
	nd_log (NDLOG_INF, "\t- hiware user account        :%s", hiauth_input_data->sHiAuthId);
	nd_log (NDLOG_INF, "\t- hiware user password       :%s", hiauth_input_data->sHiAuthPw);

	nd_log (NDLOG_INF, "--------------------------------------------------------------------");
	nd_log (NDLOG_INF, "====================================================================");


	/*
		// Send the hiware account information to the API server to perform authentication.
	*/	

	retval = requestHiwareAuthToApiServer(hiauth_input_data->sHiAuthId, hiauth_input_data->sHiAuthPw, &hi_hiwareauth_ret);
	if (retval != HI_AUTH_RET_SUCCEED || hi_hiwareauth_ret.ret != 200 )
	{
		syslog (LOG_ERR, "[%s]%s", hi_hiwareauth_ret.errorcode, hi_hiwareauth_ret.message);
		header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                header.iMsgCode = PACK_MSG_CODE_REJECT_PASSWD;

		snprintf (szErrMsg, sizeof (szErrMsg), "[%s]%s", hi_hiwareauth_ret.errorcode, hi_hiwareauth_ret.message);

		logitem =  create_archive_log ("NDAPAM-LOGIN", agent_id, agt_auth_no, uuid_str, "", (user_info.isConsole == true)? "console" : "terminal", 
						user_info.ip_address, "NDAPAM-HIWARE-AUTH",  user_info.username, hiauth_input_data->sHiAuthId, "", szErrMsg, false);

		/*
                snprintf (logitem.prefix,       ND_PREFIX_MAX_LEN ,     "NDAPAM-LOGIN");
                logitem.prefix[ND_PREFIX_MAX_LEN - 1] = '\0';
                snprintf (logitem.agentId,      ND_PREFIX_MAX_LEN,      agent_id);
                snprintf (logitem.agtAuthNo,    ND_AGTAUTHNO_MAX_LEN,   agt_auth_no);
                snprintf (logitem.sessionKey,   ND_UUID_LENGTH,         uuid_str);
                snprintf (logitem.connect_type, ND_CONNECTTYPE_MAX_LEN, (user_info.isConsole == true)? "console" : "terminal");
                snprintf (logitem.sourceIp,     ND_SOURCEIP_MAX_LEN,    user_info.ip_address);
                snprintf (logitem.last_auth_type, ND_LASTAUTHTYPE_MAX_LEN, "NDAPAM-HIWARE-AUTH");
                snprintf (logitem.sys_account,  ND_SYSACCOUNT_MAX_LEN,  user_info.username);
                snprintf (logitem.message,      ND_LOGMSG_MAX_LEN,       "[%s]%s", hi_hiwareauth_ret.errorcode, hi_hiwareauth_ret.message);
                logitem.result = false;
		*/

                nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);

		free_archive_log(logitem);

		free ((void*)agent_id);
                free ((void*)agt_auth_no);
		return PAM_AUTH_ERR;
		// API SERVER 연결 후 다시 처리 해야 함
	}

//	snprintf (logitem.hiware_account, sizeof (logitem->hiware_account), "%s", hiauth_input_data->sHiAuthId);

	memset (sDataLastLoginStatus, 0x00, sizeof (sDataLastLoginStatus));
	snprintf (sDataLastLoginStatus, sizeof (sDataLastLoginStatus), "NDAPAM-HIWARE-AUTH");

	if (strlen (g_sDataTemporaryAccessKey) > 0)
	{

		nd_log (NDLOG_INF, "HIWARE account authentication task with the authentication server succeeded.");

		retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &hiwareTwoFactData, sTwoFactString);
		nd_log (NDLOG_TRC, "OTP value entered by the user is [%s].", hiwareTwoFactData);
		/*
			// Send the OTP information to the API server to perform authentication.
		*/
		retval = requestTwoFactAuthToApiserver("08", g_sDataTemporaryAccessKey, "1", hiwareTwoFactData, "",&hi_twofact_ret);
		if (retval != HI_AUTH_RET_SUCCEED)
		{
			snprintf (szErrMsg, sizeof (szErrMsg), "[%s]%s", hi_twofact_ret.errorcode, hi_twofact_ret.message);

                	logitem =  create_archive_log ("NDAPAM-LOGIN", agent_id, agt_auth_no, uuid_str, "", (user_info.isConsole == true)? "console" : "terminal", 
							user_info.ip_address, "NDPAM-HIWARE-OTP",  user_info.username, hiauth_input_data->sHiAuthId, "", szErrMsg, false);
			/*
			
			snprintf (logitem.prefix,       ND_PREFIX_MAX_LEN ,     "NDAPAM-LOGIN");
			logitem.prefix[ND_PREFIX_MAX_LEN - 1] = '\0';
			snprintf (logitem.agentId,      ND_PREFIX_MAX_LEN,      agent_id);
			
			snprintf (logitem.agtAuthNo,    ND_AGTAUTHNO_MAX_LEN,  "%s",  (char*)agt_auth_no);

			snprintf (logitem.sessionKey,   ND_UUID_LENGTH,         "%s", uuid_str);
			snprintf (logitem.connect_type, ND_CONNECTTYPE_MAX_LEN, (user_info.isConsole == true)? "console" : "terminal");
			snprintf (logitem.sourceIp,     ND_SOURCEIP_MAX_LEN,    user_info.ip_address);
			snprintf (logitem.last_auth_type, ND_LASTAUTHTYPE_MAX_LEN, "NDPAM-HIWARE-OTP");
			snprintf (logitem.sys_account,  ND_SYSACCOUNT_MAX_LEN,  user_info.username);
			snprintf (logitem.message,      ND_LOGMSG_MAX_LEN,      "[%s] %s",hi_twofact_ret.errorcode, hi_twofact_ret.message);
			logitem.result = false;
			*/

			nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);

			free_archive_log(logitem);

			free ((void*)agent_id);
                        free ((void*)agt_auth_no);

			return PAM_AUTH_ERR;
		}

		memset (sDataLastLoginStatus, 0x00, sizeof (sDataLastLoginStatus));
        	snprintf (sDataLastLoginStatus, sizeof (sDataLastLoginStatus), "NDAPAM-HIWARE-OTP");

		syslog (LOG_ERR , "requestTwoFactAuthToApiserver RET SUCCESS");

	}
	else
	{
		if (g_sDataUserLoginResult == NULL || strcmp (g_sDataUserLoginResult, PAM_LOGIN_RESULT_FALSE) == 0 )
		{
			syslog (LOG_ERR, "fail to login api server..loginResult is not true");

			free ((void*)agent_id);
                        free ((void*)agt_auth_no);
			return PAM_AUTH_ERR;
		}
	}

	header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
	header.iMsgCode = PACK_MSG_CODE_REJECT_PASSWD;

	logitem =  create_archive_log ("NDAPAM-LOGIN", agent_id, agt_auth_no, uuid_str, "", (user_info.isConsole == true)? "console" : "terminal",
                                                        user_info.ip_address, sDataLastLoginStatus,  user_info.username, hiauth_input_data->sHiAuthId, "", "logged in successfully ", true);
	/*

	snprintf (logitem.prefix,       ND_PREFIX_MAX_LEN,       "NDAPAM-LOGIN");
	logitem.prefix[ND_PREFIX_MAX_LEN - 1] = '\0';
	snprintf (logitem.agentId,      ND_AGENTID_MAX_LEN,      agent_id);
	snprintf (logitem.agtAuthNo,    ND_AGTAUTHNO_MAX_LEN,    (char*)agt_auth_no);
	snprintf (logitem.sessionKey,   ND_UUID_LENGTH,          uuid_str);
	snprintf (logitem.connect_type, ND_CONNECTTYPE_MAX_LEN,  (user_info.isConsole == true)? "console" : "terminal");
	snprintf (logitem.sourceIp,     ND_SOURCEIP_MAX_LEN,     user_info.ip_address);
	snprintf (logitem.last_auth_type, ND_LASTAUTHTYPE_MAX_LEN,  sDataLastLoginStatus);
	snprintf (logitem.sys_account,  ND_SYSACCOUNT_MAX_LEN,   user_info.username);
	snprintf (logitem.message,      ND_LOGMSG_MAX_LEN,      "User '%s' logged in successfully from IP '%s' using '%s'", user_info.username, user_info.ip_address, "ssh");
	logitem.result = true;
	*/
	
	nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);


	memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));

	snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_ACTUAL_NAME_FORMAT, hiauth_input_data->sHiAuthId);
	pam_putenv(pamh, sDataEnv_var);

	memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));

	snprintf (sDataEnv_var, sizeof (sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str);
	pam_putenv(pamh, sDataEnv_var);

	free_archive_log(logitem);

	free ((void*)agent_id);
        free ((void*)agt_auth_no);

	return 0;
}

/*
	//
*/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
	(void)flags;
	(void)argc;
	(void)argv;
	
	int 	retval = 0;//, sock = 0;
	bool 	bisAlive_server = false;
	bool 	isSuSession 	= false;
	bool    isNdShell 	= false;
	struct 	st_pam_conf		pam_conf;
	struct 	pam_user_info           user_info;
	char	*uuid_str;//= malloc(ND_UUID_LENGTH + 1);

	/*
		// log item
	*/
	char	sUserAccount[MAX_ACCOUNT_LEN];
	char 	sSwitchAccount[MAX_ACCOUNT_LEN];
	char 	sIpAddress[IPV4_BUFFER_SIZE];
	char 	sDataCollectLog[MAX_STRING_LENGTH];
	char    sDataEnv_var[MAX_ENV_STR_LEN];
	char 	local_ip[INET_ADDRSTRLEN];


	char *user_shell = NULL;

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
                sDataHomeDir = strdup(PRODUCT_NM);

	struct _msg_header_      header = {
        	.iMsgVer     		= 0,
        	.iMsgTotalSize  	= 0

	};

	if (g_sConfFilePath == NULL )
		g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	setAgentId("5");

	sprintf ((char *)header.sAgentId, g_sDataAgentId);
        sprintf ((char *)header.iMsgVer, "%s", ND_PAM_VERSION);

	/*
		// Initialization of necessary variables for authentication tasks
	*/
	initializeAuthVariables();

        get_local_ip(local_ip, sizeof(local_ip));

	/*
		// creat new uuid
	*/	
	uuid_str = generate_uuid();

	nd_log (NDLOG_INF, "generated the session ID value [%s]", uuid_str);

	/*
		// get pam config
	*/
	getpamconf (&pam_conf);
	
	/*
		// get user session info
	*/
	get_user_info(&user_info, pamh);

	/*
		// check api server connect
	*/
	bisAlive_server = check_server_connection(pam_conf.auth_ip, pam_conf.auth_port);
	if (bisAlive_server)	{

	}

	/*
		// check os login result
	*/
	if (user_info.login_status != 0) // success 0, failed 1
	{
		nd_log (NDLOG_INF, "Login attempt failed for system account %s.",user_info.username);
		pam_syslog (pamh, LOG_ERR, "pam_sm_authenticate -- login failed");
		return PAM_AUTH_ERR;
	}

	/*
	retval = get_shell_from_pam(pamh, &user_shell);
	if (retval != PAM_SUCCESS)
	{
		pam_syslog (pamh, LOG_ERR, "user_shell IS NULL");
	}
	*/

	isNdShell = is_pam_user_ndshell(pamh);
	
	pam_syslog (pamh, LOG_ERR, "user shell is %s, %d",user_shell, isNdShell);

	/*
		 // get login type (su? terminal, console)
	*/
	retval = check_session_type(pamh, user_info.tty, user_info.service);
	switch ( retval )
	{
		/*
			// 
		*/
		case	AUTH_PURPOS_CONSOLE:
		{
			sprintf (sUserAccount, user_info.username);
		}
		break; 
	
		case 	AUTH_PURPOS_TERMINAL:
		{
			sprintf (sUserAccount, user_info.username);
		}
		break;

		case 	AUTH_PURPOS_SU:
		{
			isSuSession = true;

			const char 	*remoteAccount;
			const char      *switch_user;
			pam_client_info info ;

			info = get_su_master_info(pamh);
			if (info.ip)
			{
				strncpy (sIpAddress, info.ip, sizeof (sIpAddress));
				if (user_info.ip_address == NULL)
				{
					user_info.ip_address =(char*) malloc( IPV4_BUFFER_SIZE);
				}
				strncpy (user_info.ip_address, info.ip, sizeof (sIpAddress));
			}
			else 
				strcpy (sIpAddress, "unknown");

			retval = pam_get_item (pamh, PAM_RUSER, (const void**)&remoteAccount);
			if (retval != PAM_SUCCESS || remoteAccount == NULL )
				strcpy (sUserAccount, "unknown");
			else 
				strcpy (sUserAccount, remoteAccount);

			retval = pam_get_user (pamh, &switch_user, NULL);
			if (retval != PAM_SUCCESS || switch_user == NULL )
				strcpy (sSwitchAccount, "unknown");
			else
				strcpy (sSwitchAccount, switch_user);

			const char *remote_ip;
			retval = pam_get_item(pamh, PAM_RHOST, (const void **)&remote_ip);
                	if (retval == PAM_SUCCESS && remote_ip)
                	{
                        	//snprintf (ip_address, sizeof (ip_address), remote_ip);
				syslog (LOG_ERR, "remote_ip : %s", remote_ip);
                	}
			else
				syslog (LOG_ERR, "REMOTE_IP NOT GET.."); 


			const char *connectipaddr = pam_getenv(pamh, "HIWARE_SSH_CLIENT_IP");
			if (connectipaddr)
				syslog (LOG_ERR, "SU : GET CONNECT IP :%s", connectipaddr);
			else
				syslog (LOG_ERR, "su : fail to get connect ip env");


			PamPolicy pamPolicy = parsePamPolicy(/*PAM_RULE_FILE*/ getPamRuleFilePath(sDataHomeDir));
        		Rule *matchedRule = isPamPolicyMatched(&pamPolicy, user_info.ip_address, user_info.username);	
			if (isSuPamPolicyMatched(&pamPolicy, user_info.ip_address, user_info.username,sSwitchAccount) == false)
			{
				freePamPolicy(&pamPolicy);
				const char *error_msg = "Access denied: You do not have permission to access this resource.";
				pam_set_item(pamh, PAM_USER, error_msg);
				
				return PAM_PERM_DENIED;
			}
			sprintf (user_info.agtAuthNo, "%s", matchedRule->agtAuthNo);

			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_AGTAUTHNO_KEY_FORMAT, matchedRule->agtAuthNo);
                	pam_putenv(pamh, sDataEnv_var);


			freePamPolicy(&pamPolicy);

			//const char *error_msg_ = "Unregistered user. Please register and try again.";
			//pam_set_item(pamh, PAM_USER, error_msg_);
		}
		break;

		default:
		break;
	}


	/*
		// Proceed with hiware login and two-factor authentication login tasks through discussions with the API server and return the results.
	*/

	if (isSuSession == false)
	{

		retval = nd_pam_authenticate_user(uuid_str, user_info, pamh);
		if (retval != PAM_SUCCESS)
		{
			syslog (LOG_ERR, "nd_pam_authenticate_user -- FALSE");
			return retval;
		}

	}

	nd_log (NDLOG_INF, "The user's login attempt was successful. The login process has been completed successfully.");

	/*
		// Processing logic during the execution of the 'su' command.
	*/
	if (isSuSession)
	{
		/*
			// When an update to the environment variables is required, proceed with the following steps.
		*/
		if (user_info.bNeedtoEnvUpdata)
		{
			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_ACTUAL_NAME_FORMAT, user_info.switchuserActualNm);
			pam_putenv(pamh, sDataEnv_var);
			memset (sDataEnv_var, 0x00, sizeof (sDataEnv_var));

			snprintf(sDataEnv_var, sizeof(sDataEnv_var),HIWARE_SESSION_KEY_FORMAT, uuid_str);
			pam_putenv(pamh, sDataEnv_var);

		}
		/*
                	// write su control log
        	*/
		header.iMsgType = PACK_MSG_TYPE_SU_AUTH;
        	header.iMsgCode = PACK_MSG_CODE_ATTEMPTS_SWITCH;

		nd_pam_sulog (header,(char*) sDataHomeDir, user_info.agtAuthNo, g_sDataAgentId,  user_info.username, user_info.switchusernname, user_info.service, sIpAddress, uuid_str, sDataCollectLog );
	}else
	{
		
	}	

	return retval;
};

/*
        //Function Definition of Linux PAM Module [pam_sm_setcred]
*/
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                             int argc, const char **argv) {
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}

/*
        //Function Definition of Linux PAM Module [pam_sm_acct_mgmt]
*/
/*
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {

	return PAM_SUCCESS;
}
*/
/*
        //Function Definition of Linux PAM Module [pam_sm_open_session]
*/
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) 		{
	(void)flags;
	(void)argc;
	(void)argv;

	system("clear");
	
	const char *service;
	const char *remote_ip;
	bool isConsole = 0;
	bool isNdShell = 0;
	
	char ip_address[INET_ADDRSTRLEN];
	const char *tty;
	const char *username;
	char *session_id = NULL;// = malloc(SESSION_ID_LENGTH + 1); 
	int retval;
	bool isSuSession = false;
	char sSuType[128] = {0,};

	pam_config config = {0};

	char action_type[128];
	struct _archive_log                             logitem;

	pam_client_info info ;

	struct _msg_header_             header = {

		.iMsgTotalSize  = 0
	};

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
                sDataHomeDir = strdup(PRODUCT_NM);

	if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	setAgentId("5");

	sprintf ((char*)header.sAgentId, g_sDataAgentId);
	sprintf ((char*)header.iMsgVer, "%s", ND_PAM_VERSION);

	if (read_pam_config(g_sConfFilePath, &config) != 0)    {
	/*                if (strcmp(config.pam_mode,"ON") != 0 )
				return PAM_SUCCESS;
	*/		
		return PAM_SUCCESS;
	}

	parse_ssh_connection(pamh);

	/*
		// If the operating mode applied in the configuration file is OFF, do not proceed with the authentication and output operations.
	*/
	if (strcmp(config.pam_mode,"ON") == 0 )
	{
		/*
			// Proceed with displaying the SSH login banner and warning message.
		*/
		print_nd_banner ();

		print_nd_warnning_msg ();
	}

	/*
		// Check the services used in the session's connection information.
	*/
	retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	/*
		// Proceed with processing if the entered command is either 'su' or 'su -l'. Detect both cases based on the usage of the 'su' command.
	*/
	if (service != NULL && (strcmp (service, STR_SU) == 0 || strcmp (service, STR_SUL) == 0))
	{
		snprintf (sSuType,sizeof (sSuType), service);
		isSuSession = true;
	}

	/*
		// get the user name in the session's connection information
	*/
	if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
		return PAM_SYSTEM_ERR;
	}

	session_id = generate_uuid();
	
	/*
		//
	*/
	isNdShell = is_pam_user_ndshell(pamh);
	if (isNdShell)
	{

	}
	
	/*
		// get the tty information in the session's connection information
	*/
	pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	if (tty)        {

		if (strncmp(tty, "tty", 3) == 0 )       {
			isConsole = true;
		}
	}

	//pid_t ttypid = 0;
	const char* tty_name;
    	if (pam_get_item(pamh, PAM_TTY, (const void**)&tty_name) != PAM_SUCCESS || !tty_name) {
        	pam_syslog(pamh, LOG_ERR, "Failed to get TTY name");
        	return PAM_AUTH_ERR;
    	}
		
	/*
		// get ssh connection information in the environment variable
		// ex ) SSH_CONNECTION=172.28.112.1 49495 172.28.113.91 22
	*/
	const char *ssh_connection = getenv(ENV_SSHCONNECTION);
	if (ssh_connection)
	{
			char *token = strtok((char *)ssh_connection, " ");
			if (token != NULL) {
				strncpy(ip_address, token, sizeof(ip_address));
				ip_address[sizeof(ip_address) - 1] = '\0';
				strncpy(info.ip, token, INET_ADDRSTRLEN);
				info.ip[INET_ADDRSTRLEN - 1] = '\0';
				token = strtok(NULL, " ");
				if (token != NULL) 	{
					strncpy(info.port, token, sizeof(info.port));
					info.port[sizeof(info.port) - 1] = '\0';
				}
			}
			else
			{
				/*
					// If information cannot be collected, indicate it as NONE.
				*/
				strcpy(ip_address, "NONE");
			}
	}
	else
	{


		/*
		if (isSuSession)
			return PAM_SUCCESS;
		*/
		
		/*
			// Collect information related to 'su' if it is not an SSH login.
		*/
		syslog (LOG_ERR, "get_su_master_info CALL..");
		info = get_su_master_info(pamh);
		strncpy (ip_address, info.ip ? info.ip : "NONE", sizeof (ip_address));
	}

	/*
		// If the access session is not a CONSOLE connection, it is considered a terminal connection.
	*/
	if (!isConsole  )        {
		retval = pam_get_item(pamh, PAM_RHOST, (const void **)&remote_ip);
		if (retval == PAM_SUCCESS && remote_ip) 	{
				snprintf (ip_address, sizeof (ip_address), remote_ip);
		} 	
	}
	else
	{
			remote_ip = PAM_LOOPIPADDR;
			snprintf (ip_address, sizeof (ip_address), remote_ip);
	}

	/*
		// Retrieve the previous username (in the case of PAM_RUSER, it is possible to obtain the target of the operation).
	*/
	const char * previous_user;
	retval = pam_get_item(pamh, PAM_RUSER, (const void **)&previous_user);
	if (retval != PAM_SUCCESS || previous_user == NULL) {
		previous_user = "unknown";
	}

	int pri_no, action, logging;
        char *agt_auth_no;
        const char *agent_id = get_value_as_string(getPamRuleFilePath( sDataHomeDir), "agentId");

        if (check_pam_policy (getPamRuleFilePath( sDataHomeDir), ip_address, username, &pri_no, &agt_auth_no, &action, &logging))
	{
		
	}

	/*
		// The session key set during authentication is retrieved from the environment variable.
	*/
	const char *agtAuthNo = pam_getenv(pamh, ENV_HIWARE_AGTAUTHNO);

	header.iMsgType = isSuSession ? PACK_MSG_TYPE_SU_SESSION : PACK_MSG_TYPE_SSH_SESSION;
    	header.iMsgCode = PACK_MSG_CODE_SESSION_OPEN;

	//nd_pam_session_log ( header,(char*) sDataHomeDir, (char*)agtAuthNo, g_sDataAgentId,ND_PREFIX_LOGIN, session_id, (char*)username, uid, gid, isConsole, ip_address, (long)time(NULL), (char*)sessionkey, szCollectLogBuff); 
	sprintf (action_type, isSuSession ? "su:session": "sshd:session");

	snprintf (logitem.prefix,       ND_PREFIX_MAX_LEN ,     "NDAPAM-SESSION");
	logitem.prefix[ND_PREFIX_MAX_LEN - 1] = '\0';
	snprintf (logitem.agentId,      ND_PREFIX_MAX_LEN,      "%s",agent_id);
	snprintf (logitem.agtAuthNo,    ND_AGTAUTHNO_MAX_LEN,   "%s",agtAuthNo);

	snprintf (logitem.sessionKey,   ND_UUID_LENGTH,         "%s", session_id);
	snprintf (logitem.connect_type, ND_CONNECTTYPE_MAX_LEN, (isConsole == true)? "console" : "terminal");
	snprintf (logitem.sourceIp,     ND_SOURCEIP_MAX_LEN,    ip_address);
	snprintf (logitem.last_auth_type, ND_LASTAUTHTYPE_MAX_LEN, "NDAPAM-SESSION-CREATE");
	snprintf (logitem.sys_account,  ND_SYSACCOUNT_MAX_LEN,  username);
	snprintf (logitem.message,      ND_LOGMSG_MAX_LEN,      "New session created");
	logitem.result = true;

	nd_pam_archive_log(header, logitem, (char*) sDataHomeDir);

	free(session_id);
	return PAM_SUCCESS;
}

/*
        //Function Definition of Linux PAM Module [pam_sm_close_session]
*/
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) 	{

	(void)argc;
	(void)argv;
	(void)flags;

	const char *remote_ip;
	char hostname[256];
	int retval;
	const char *tty;
	bool isConsole = false;
	bool isNdShell = false;
	bool isSuSession = false;
	const char *username;
	const char *service;
	char sSuType[128] = {0,};

	const char * szClientPort;
	char ip_address[INET_ADDRSTRLEN];

	char 		action_type[128] = {0,};
	char szCollectLogBuff[1024];

	const char *previous_user;  // 바로 이전 사용자
    	const char *target_user;

	pam_client_info info ;

	struct _archive_log                             logitem;

	struct _msg_header_ header = {

		.iMsgTotalSize  = 0
	};

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
                sDataHomeDir = strdup(PRODUCT_NM);

	if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	setAgentId("5");

	sprintf ((char*)header.sAgentId, g_sDataAgentId);
	sprintf ((char*)header.iMsgVer, "%s", ND_PAM_VERSION);

	const char *agtAuthNo = pam_getenv(pamh, ENV_HIWARE_AGTAUTHNO);

	/*
		// The session key set during authentication is retrieved from the environment variable.
	*/
	const char *sessionkey = pam_getenv(pamh, ENV_HIWARE_SESSIONKEY);

	/*
		// Retrieve the username of the logged-in user from the session.
	*/
	if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
		return PAM_SYSTEM_ERR;
	}

	/*
                //
        */
        isNdShell = is_pam_user_ndshell(pamh);
	if (isNdShell)
	{

	}

	/*
		// Check the services used in the session's connection information.
	*/
	retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (retval != PAM_SUCCESS) 		{
			return retval;
	}

	/*
		// Proceed with processing if the entered command is either 'su' or 'su -l'. Detect both cases based on the usage of the 'su' command.
	*/
	if (service != NULL && (strcmp (service, STR_SU) == 0 || strcmp (service, STR_SUL) == 0))
	{
		snprintf (sSuType, sizeof (sSuType), service);
		isSuSession = true;

		const char *previous_user;
		const char *target_user;

		/*
			// get ssh connection information in the environment variable
			// ex ) SSH_CONNECTION=172.28.112.1 49495 172.28.113.91 22
		*/
		const char *ssh_connection = getenv(ENV_SSHCONNECTION);
		char ip_address[INET_ADDRSTRLEN];

		if (ssh_connection)
		{
			char *token = strtok((char *)ssh_connection, " ");
			if (token != NULL) {

				strncpy(ip_address, token, sizeof(ip_address));
				ip_address[sizeof(ip_address) - 1] = '\0';
				strncpy(info.ip, token, INET_ADDRSTRLEN);
				info.ip[INET_ADDRSTRLEN - 1] = '\0';
				token = strtok(NULL, " ");
				if (token != NULL) {
					strncpy(info.port, token, sizeof(info.port));
					info.port[sizeof(info.port) - 1] = '\0';
				}
			}
			else
			{
				strcpy(ip_address, "NONE");
			}
		}
		else
		{
			info = get_su_master_info(pamh);
			strncpy (ip_address, info.ip ? info.ip : "NONE", sizeof (ip_address));
		}

		previous_user= getenv("USER") ? getenv ("USER") : "unknown";

		retval = pam_get_user(pamh, &target_user, NULL);
		if (retval != PAM_SUCCESS || target_user == NULL) {
			return PAM_AUTH_ERR;
		}

		/*
			//
		*/
		header.iMsgType = PACK_MSG_TYPE_SU_SESSION;
		header.iMsgCode = PACK_MSG_CODE_SESSION_CLOSE;

		char message[128] = {0,};
		sprintf (message, "Account %s attempts switch to %s using \'su\'",target_user, ( char *) previous_user);
		
		nd_pam_log(header, (char*)sDataHomeDir, (char*)agtAuthNo, g_sDataAgentId, "su:session", "attempts switch",(char*)username,info.ip,(char*)sessionkey,szCollectLogBuff,
				message);


		retval = get_pam_data (pamh, "ND_CLIENT_PORT", (const void **)&szClientPort);

		if (strlen (info.port) <= 0 )
			sprintf (info.port, szClientPort);


		nd_pam_sulog (header, (char*)sDataHomeDir, (char*)agtAuthNo, g_sDataAgentId,  ( char *) target_user, ( char *) previous_user, ( char *) service, info.ip, (char*)sessionkey, szCollectLogBuff);
	}

	// 호스트 이름 가져오기
	if (gethostname(hostname, sizeof(hostname)) != 0) 	{
		nd_log (NDLOG_ERR, "Failed to obtain the hostname.");
	}

	// TTY 정보 가져오기
	pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	if (tty)        {

		if (strncmp(tty, "tty", 3) == 0 )       {
			isConsole = true;
		}
	}

	if (isConsole == false )        
	{
		retval = pam_get_item(pamh, PAM_RHOST, (const void **)&remote_ip);
		if (retval == PAM_SUCCESS && remote_ip) 
		{	
			snprintf (ip_address, sizeof (ip_address), remote_ip);
		} else 
		{
			const char *ssh_connection = getenv(ENV_SSHCONNECTION);
			if (ssh_connection)
			{
				char *token = strtok((char *)ssh_connection, " ");
				if (token != NULL) {

					strncpy(ip_address, token, sizeof(ip_address));
					ip_address[sizeof(ip_address) - 1] = '\0';
				}
				else
				{
					strcpy(ip_address, "NONE");
				}
			}
			else
			{
				/*
					// Collect information related to 'su' if it is not an SSH login.
				*/
				info = get_su_master_info(pamh);
				strncpy(ip_address, info.ip ? info.ip : "NONE", sizeof(ip_address));
			}
		}
	}
	else
	{	
		/*
			// IP information will be represented as the loopback IP if it cannot be retrieved.
		*/
		snprintf(ip_address, sizeof(ip_address), "%s", PAM_LOOPIPADDR);
	}

	/*
		// The name of the user attempting to log in remotely is represented, as well as the name of the user who entered the command during the su operation.
	*/
	retval = pam_get_item(pamh, PAM_RUSER, (const void **)&previous_user);
	if (retval != PAM_SUCCESS || previous_user == NULL) {
		 previous_user = "unknown";
	}
	
	/*
		// The username of the current session is retrieved.
	*/
	retval = pam_get_user(pamh, &target_user, NULL);
	if (retval != PAM_SUCCESS || target_user == NULL) {
		return PAM_AUTH_ERR;
	}

	// 액션 타입 설정
    	sprintf(action_type, isSuSession ? "su:session" : "sshd:session");

	header.iMsgType = isSuSession ? PACK_MSG_TYPE_SU_SESSION : PACK_MSG_TYPE_SSH_SESSION;
	header.iMsgCode = PACK_MSG_CODE_SESSION_CLOSE;

	snprintf (logitem.prefix,       ND_PREFIX_MAX_LEN ,     "NDAPAM-SESSION");
	logitem.prefix[ND_PREFIX_MAX_LEN - 1] = '\0';
	snprintf (logitem.agentId,      ND_PREFIX_MAX_LEN,      "1");
	snprintf (logitem.agtAuthNo,    ND_AGTAUTHNO_MAX_LEN,  "1"/*,  (char*)matchedRule->agtAuthNo*/);

	snprintf (logitem.sessionKey,   ND_UUID_LENGTH,         (sessionkey != NULL)? sessionkey : "");
	snprintf (logitem.connect_type, ND_CONNECTTYPE_MAX_LEN, (isConsole == true)? "console" : "terminal");
	snprintf (logitem.sourceIp,     ND_SOURCEIP_MAX_LEN,    ip_address);
	snprintf (logitem.last_auth_type, ND_LASTAUTHTYPE_MAX_LEN, "NDAPAM-SESSION-TERMINATE");
	snprintf (logitem.sys_account,  ND_SYSACCOUNT_MAX_LEN,  username);
	snprintf (logitem.message,      ND_LOGMSG_MAX_LEN,      "Session terminated.");
	logitem.result = true;

	nd_pam_archive_log(header, logitem, (char*)sDataHomeDir);

	return PAM_SUCCESS;
}

/*
        //Function Definition of Linux PAM Module [pam_sm_chauthtok]
*/
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh , int flags,
                               int argc, const char **argv) 	{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	return PAM_SUCCESS;
}

__attribute__((constructor)) void init() {

	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);
	pthread_mutex_init(&session_id_mutex, NULL); // 뮤텍스 초기화
}

__attribute__((destructor)) void cleanup() {
	pthread_mutex_destroy(&session_id_mutex); // 뮤텍스 정리
}
