
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
char * g_sDataHiwareUserNumber;

char g_sDataRandomUrl[MAX_URL_LEN];
char g_sDataUserLoginUrl[MAX_URL_LEN];
char g_sDataSystemLoginUrl[MAX_URL_LEN];
char g_sDataTwoFactLoginIrl[MAX_URL_LEN];

int g_nDataSshPort = 0;

char * g_sConfFilePath;

char g_sDataAgentId[2];


//static const char *current_user;

pthread_mutex_t session_id_mutex;

/*
*/
#define PAM_HIWARE_SSH_SERVER_IP 	"HIWARE_SSH_CLIENT_IP"
#define PAM_HIWARE_SSH_SERVER_PORT	"HIWARE_SSH_SERVER_PORT"
#define PAM_HIWARE_SSH_CLIENT_IP	"HIWARE_SSH_CLIENT_IP"
#define PAM_HIWARE_SSH_CLIENT_PORT	"HIWARE_SSH_CLIENT_PORT"


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
	//
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
/*
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
*/
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
	// Validate input arguments
	if (tty == NULL || service == NULL) {
		return -1;
	}

	const char *ruser = NULL; // Original user who initiated the session
	const char *current_tty = NULL;

	// Get the original user (RUSER)
	if (pamh != NULL) {
		if (pam_get_item(pamh, PAM_RUSER, (const void **)&ruser) != PAM_SUCCESS) {
		    	ruser = "unknown"; // Default to "unknown" if retrieval fails
		}


		// Get the current TTY (PAM_TTY)
		if (pam_get_item(pamh, PAM_TTY, (const void **)&current_tty) != PAM_SUCCESS) {
		    	current_tty = "unknown"; // Default to "unknown" if retrieval fails
		}
	} else {
	}

	/*
	// Log the retrieved information
	syslog(LOG_INFO, "Session check: TTY=%s, Service=%s, RUSER=%s",
	   	current_tty ? current_tty : "NULL",
	   	service,
	   	ruser ? ruser : "NULL");
	*/
	// Determine session type based on TTY
	if (strncmp(tty, "tty", 3) == 0) {
		return AUTH_PURPOS_CONSOLE; // Console login
	} else if (strncmp(tty, "/pts/", 5) == 0) {
		if (ruser && strcmp(ruser, "root") != 0) {
			return AUTH_PURPOS_SU; // User switching via su
		}
		return AUTH_PURPOS_TERMINAL; // Regular terminal login
	}

	// Determine session type based on service
	if (strcmp(service, "su") == 0 || strcmp(service, "sul") == 0) {
		return AUTH_PURPOS_SU;
	}

	//syslog(LOG_ERR, "[ERR] Unable to determine session type\n");
	return -1; // Default case

}


int nd_pam_authenticate_user (char * uuid_str, /*struct pam_user_info*/SessionInfo * user_info, pam_handle_t * pamh)
{
	int authsvr_port = 0;
	int retval = 0;

	bool 	bRetPamPolicy = false, bRetSamPolicy = false;

	char  	*hiwareTwoFactData = NULL;
	char 	sTwoFactString[128];
	char    sDataEnv_var[MAX_ENV_STR_LEN];
	char 	szErrMsg[1024] = {0,};

	char    svrConnStartTime[ND_TIME_MAX_LEN] = {0,};
        char    svrConnEndTime[ND_TIME_MAX_LEN] = {0,};
        char    svrConnRstTpCode [4] = {0,};
        char    svrConnFailRsnCode [4] = {0,};
        char    agtNo[16] = {0,};
        char    agtConnFormTpCode[4] = {0,};
        char    agtAuthNo[ND_AGTAUTHNO_MAX_LEN] = {0,};
        char    portNo[8] = {0,};
        char    userIp[ND_SOURCEIP_MAX_LEN] = {0,};
        char    securStepNo[ND_SECUR_STEP_NO_MAX_LEN] = {0,};
        char    svrConnSessKey[ND_UUID_LENGTH] = {0,};
        char    connAcctId[ND_SYSACCOUNT_MAX_LEN] = {0,};
	char    switchAcctId[ND_SYSACCOUNT_MAX_LEN] = {0,};
        char    pamAgtAuthNo[ND_AGTAUTHNO_MAX_LEN] = {0,};
        char    userNo[18] = {0,};
        char    pamCertDtlCode[4] = {0,};
	char 	pamCertDtlAuthCode[4] = {0,};

        char    certTpCode[ND_CERT_TP_CODE_MAX_LEN] = {0,};
        char    certAppTpCode[ND_CERT_APP_TP_CODE_MAX_LEN] = {0,};
        char    certSucesFailYn[ND_CERT_APP_SUCES_FAIL_YN_MAX_LEN] = {0,};
        char    certStepSeqNo[ND_CERT_STEP_SEQ_NO_MAX_LEN] = {0,};

	char    sDataLastLoginStatus[ND_LASTAUTHTYPE_MAX_LEN] = {0,};	

	sprintf (sTwoFactString, "OTP(One-Time Password): ");
	sprintf (pamCertDtlAuthCode, "%s", PAM_CERT_DTL_AUTH_OS);
	snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);

	struct _archive_log 			*logitem;
	struct st_hiauth_input_data    		*hiauth_input_data;
	st_hiauth_twofact_login_result		hi_twofact_ret;
	struct st_hiauth_hiware_login_result 	hi_hiwareauth_ret;

	struct _msg_header_   header = {
        	.iMsgVer        = 0,
        	.iMsgTotalSize  = 0
	};

	header.iMsgType = 0;
        header.iMsgCode = PAM_AGT_AUTH_CODE;

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
		sDataHomeDir = strdup(PRODUCT_NM);

	if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	/*
		// Retrieve the server connection information from the configuration file.
	*/
	char * auth_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERIP);
    	char * auth_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERPORT); 
	char * authsvr_emergency_act = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,PAM_AUTHSVR_EMERGENCY_ACTION);

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

	int pam_pri_no, pam_action, pam_logging, sam_pri_no, sam_action, sam_logging;
    	char *agt_auth_no, *ndshell_agtAuthNo;

	char *agent_id = get_value_as_string(getPamRuleFilePath( sDataHomeDir), "agentId");

	if (agent_id == NULL )
		retval = PAM_AUTH_ERR;

	// agtNo
        snprintf (agtNo, sizeof (agtNo), "%s", agent_id ? agent_id : "");

	// agtConnFormTpCode
        snprintf (agtConnFormTpCode, sizeof (agtConnFormTpCode), "%s", (user_info->type == 1)? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);
	
	// agtAuthNo (ndshell)

	// portNo

	// usrIp
        snprintf (userIp, sizeof (userIp), "%s", user_info->remote_host);

	// securStepNo
	snprintf (securStepNo, sizeof (securStepNo), "%s", PAM_SECUR_STEP_PAM);

	// svrConnSessKey
        snprintf (svrConnSessKey, sizeof (svrConnSessKey), "%s", uuid_str);

	// connAcctId
        snprintf (connAcctId, sizeof (connAcctId), "%s", user_info->current_user);

	// userNo
	//snprintf (userNo, ND_AGENTID_MAX_LEN, "%s", agent_id);

	// pamCertDtlCode
	snprintf (pamCertDtlCode, sizeof (pamCertDtlCode), "%s", PAM_LOGIN);

	//snpirntf (pamCertDtlAuthCode, sizeof (pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_HIWAREAUTH );

	if (check_pam_policy (getPamRuleFilePath( sDataHomeDir), user_info->remote_host, user_info->current_user, &pam_pri_no, &agt_auth_no, &pam_action, &pam_logging))
        {
		if (pam_action == PAM_ACT_RULE_DENY)
		{
			header.iMsgType = 0;

			//svrConnFailRsnCode
			snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "14");
			// svrConnRstTpCode
			snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);

			retval = PAM_PERM_DENIED;
			goto nd_pam_authenticate_user;
		}	
		else
		{
			bRetPamPolicy = true;

			retval = PAM_SUCCESS;
		}
	}

	snprintf (pamAgtAuthNo, sizeof (pamAgtAuthNo), "%s", agt_auth_no ? agt_auth_no : "");

#ifdef _SUPP_DATE_
	time_t current_time = time(NULL);
        struct tm *tm_info = localtime(&current_time);
        int current_wday = tm_info->tm_wday == 0 ? 7 : tm_info->tm_wday; // Adjust for Sunday being 7

	if (is_pam_user_ndshell(pamh) && 
		validate_json_sampolicy(getPamRuleFilePath( sDataHomeDir), user_info->remote_host, user_info->current_user, current_time, current_wday) == 1)
#else //_SUPP_DATE_
	if (is_pam_user_ndshell(pamh) && 
		validate_json_sampolicy_without_date(getPamRuleFilePath( sDataHomeDir), user_info->remote_host, user_info->current_user, &ndshell_agtAuthNo, &sam_action, &sam_logging) == 1)
#endif //_SUPP_DATE_
	{

		if (sam_action == PAM_ACT_RULE_DENY )
		{
			//SVR_CONN_FAIL_RSN_CODE : 미인가 계정 접속
			// code 14
			snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "14");

			// svrConnRstTpCode
			snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
			header.iMsgType = 0;

			retval = PAM_PERM_DENIED;
			goto nd_pam_authenticate_user;
		}
		else
		{
			bRetSamPolicy = true;

			retval = PAM_SUCCESS;
		}
	}

	snprintf (agtAuthNo, sizeof (agtAuthNo), "%s", ndshell_agtAuthNo ? ndshell_agtAuthNo : "");

	if (bRetPamPolicy == false && bRetSamPolicy == false)
		return PAM_SUCCESS;

#ifdef _DEF_BLOCK_MODE_

	if (check_pam_policy (getPamRuleFilePath( sDataHomeDir), user_info->remote_host, user_info->current_user, &pri_no, &agt_auth_no, &action, &logging))
	{
		// pamAgtAuthNo
		snprintf (pamAgtAuthNo, ND_AGTAUTHNO_MAX_LEN, "%s",agt_auth_no);
		bool isNdShell = is_pam_user_ndshell(pamh);
		if (isNdShell == true )
		{
#ifdef _SUPP_DATE_
			time_t current_time = time(NULL);
			struct tm *tm_info = localtime(&current_time);
    			int current_wday = tm_info->tm_wday == 0 ? 7 : tm_info->tm_wday; // Adjust for Sunday being 7

			retval = validate_json_sampolicy(getPamRuleFilePath( sDataHomeDir), user_info->remote_host, user_info->current_user, current_time, current_wday);
#else // _SUPP_DATE_
			retval = validate_json_sampolicy_without_date(getPamRuleFilePath( sDataHomeDir), user_info->remote_host, user_info->current_user, &ndshell_agtAuthNo);
#endif // _SUPP_DATE_
			// agtAuthNo
			snprintf (agtAuthNo, sizeof (agtAuthNo), "%s", ndshell_agtAuthNo ? ndshell_agtAuthNo : "");

			syslog (LOG_ERR, "agtAuthNo (ndshell) : %s", ndshell_agtAuthNo);
		
			if (retval == 1)	{
				//syslog (LOG_ERR, "Access granted: SAMPolicy matched.");
			}
			else
			{
				//SVR_CONN_FAIL_RSN_CODE : 미인가 계정 접속
				// code 14
				snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "14");
				// svrConnRstTpCode
				snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
				header.iMsgType = 0;

				retval = PAM_PERM_DENIED;
				goto nd_pam_authenticate_user;

			}
		}


		if (action == PAM_USER_RULE_ACT_DENY)
		{
			header.iMsgType = 0;
		
			//svrConnFailRsnCode
			snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "14");
			// svrConnRstTpCode
                        snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);

			retval = PAM_PERM_DENIED; 
			goto nd_pam_authenticate_user;
		}

		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_AGTAUTHNO_KEY_FORMAT, agt_auth_no);
        	pam_putenv(pamh, sDataEnv_var);
		retval = PAM_SUCCESS;
	}
	else
	{
		//svrConnFailRsnCode
		snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "14");
		// svrConnRstTpCode
                snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);

		header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;

		retval = PAM_PERM_DENIED;

		goto nd_pam_authenticate_user;

	}

#endif //_DEF_BLOCK_MODE_

	hiauth_input_data = OperateHiAuth(pamh);
	if ((hiauth_input_data->sHiAuthId == NULL || strlen (hiauth_input_data->sHiAuthPw) <= 0)  ||
		(hiauth_input_data->sHiAuthPw == NULL || strlen (hiauth_input_data->sHiAuthPw) <= 0))
	{
		//svrConnFailRsnCode
                snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "4");
                // svrConnRstTpCode
                snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);

		nd_log (LOG_LEVEL_ERR, "HIWARE user authentication information is missing, causing the authentication task to fail");
		retval = PAM_AUTH_ERR;

		goto nd_pam_authenticate_user;
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
	
	snprintf (pamCertDtlAuthCode, sizeof (pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_HIWAREAUTH );
	retval = requestHiwareAuthToApiServer(hiauth_input_data->sHiAuthId, hiauth_input_data->sHiAuthPw, agt_auth_no, &hi_hiwareauth_ret);
	if (retval != HI_AUTH_RET_SUCCEED || hi_hiwareauth_ret.ret != 200 )
	{
		retval = PAM_AUTH_ERR;
		
		//svrConnFailRsnCode
                snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "04");
		
		// svrConnRstTpCode
                snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);

		goto nd_pam_authenticate_user;
	}

	memset (sDataLastLoginStatus, 0x00, sizeof (sDataLastLoginStatus));
	snprintf (sDataLastLoginStatus, sizeof (sDataLastLoginStatus), "NDAPAM-HIWARE-AUTH");

	if (strlen (g_sDataTemporaryAccessKey) > 0)
	{	
		snprintf (pamCertDtlAuthCode, sizeof (pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_TWOFACT );
		nd_log (NDLOG_INF, "HIWARE account authentication task with the authentication server succeeded.");

		retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &hiwareTwoFactData, sTwoFactString);
		nd_log (NDLOG_TRC, "OTP value entered by the user is [%s].", hiwareTwoFactData);
		/*
			// Send the OTP information to the API server to perform authentication.
		*/
		retval = requestTwoFactAuthToApiserver("08", g_sDataTemporaryAccessKey, "1", hiwareTwoFactData, "",&hi_twofact_ret);
		if (retval != HI_AUTH_RET_SUCCEED)
		{
			//svrConnFailRsnCode
                	snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "06");

			// svrConnRstTpCode
                	snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);

			retval = PAM_AUTH_ERR;
			goto nd_pam_authenticate_user;
		}

		snprintf ( certTpCode,          sizeof (certTpCode),            "%s", hi_twofact_ret.certTpCode);
                snprintf ( certAppTpCode,       sizeof (certAppTpCode),         "%s", hi_twofact_ret.certAppTpCode);
                snprintf ( certSucesFailYn,     sizeof (certSucesFailYn),       "%s", hi_twofact_ret.certSucesFailYn);
                snprintf ( certStepSeqNo,       sizeof (certStepSeqNo),         "%s", hi_twofact_ret.certStepSeqNo);

		retval = PAM_SUCCESS;

		memset (sDataLastLoginStatus, 0x00, sizeof (sDataLastLoginStatus));
        	snprintf (sDataLastLoginStatus, sizeof (sDataLastLoginStatus), "NDAPAM-HIWARE-OTP");
	}
	else
	{
		if (g_sDataUserLoginResult == NULL || strcmp (g_sDataUserLoginResult, PAM_LOGIN_RESULT_FALSE) == 0 )
		{
			//svrConnFailRsnCode
                        snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "01");

			// svrConnRstTpCode
                	snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);

			retval = PAM_AUTH_ERR;

			goto nd_pam_authenticate_user;
		}
	}

	retval = PAM_SUCCESS;

	memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));
	if (g_sDataHiwareUserNumber)
	{
		snprintf (userNo, ND_AGENTID_MAX_LEN, "%s", g_sDataHiwareUserNumber);
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_USER_NUMBER_FORMAT, g_sDataHiwareUserNumber);
        	pam_putenv(pamh, sDataEnv_var);
	}	

	memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));

	snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_ACTUAL_NAME_FORMAT, hiauth_input_data->sHiAuthId);
	pam_putenv(pamh, sDataEnv_var);


	memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));

	snprintf (sDataEnv_var, sizeof (sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str);
	pam_putenv(pamh, sDataEnv_var);

nd_pam_authenticate_user:

	if (pam_logging == LOGGING_ON) 	{

		logitem =  create_archive_log (svrConnStartTime, svrConnEndTime, svrConnRstTpCode, svrConnFailRsnCode, agtNo, agtConnFormTpCode,
						agtAuthNo, portNo, userIp, securStepNo, svrConnSessKey, connAcctId, switchAcctId, pamAgtAuthNo, userNo, pamCertDtlCode,pamCertDtlAuthCode,
						certTpCode, certAppTpCode,certSucesFailYn,certStepSeqNo);

		nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
		free_archive_log(logitem);
	}

	if (agent_id)
		free (agent_id);
	if (agt_auth_no)
        	free (agt_auth_no);

	return retval;
}

void print_session_info(const SessionInfo *info) {
        if (!info) 
	{
		//syslog (LOG_ERR, "print_session_info param is null");
		return;
	}

        syslog(LOG_ERR,"Type: %d\n", info->type);
        syslog(LOG_ERR,"Current User: %s\n", info->current_user ? info->current_user : "(null)");
        syslog(LOG_ERR,"Target User: %s\n", info->target_user ? info->target_user : "(null)");
        syslog(LOG_ERR,"Remote Host: %s\n", info->remote_host ? info->remote_host : "(null)");
        syslog(LOG_ERR,"TTY: %s\n", info->tty ? info->tty : "(null)");
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
	//bool 	bisAlive_server = false;
	bool 	isSuSession 	= false;
	bool    isNdShell 	= false;
	struct 	st_pam_conf		pam_conf;
	struct 	pam_user_info           user_info;
	char	*uuid_str;//= malloc(ND_UUID_LENGTH + 1);
	struct _archive_log             *logitem = NULL;
	char	*ndshell_agtAuthNo;
	
	bool    bRetPamPolicy = false, bRetSamPolicy = false;

	int 	pam_pri_no, pam_action, pam_logging, sam_action, sam_logging;
        char 	*agt_auth_no;

	/*
		// log item
	*/
	char	sUserAccount[MAX_ACCOUNT_LEN];
	char 	sSwitchAccount[MAX_ACCOUNT_LEN];
	char 	sIpAddress[IPV4_BUFFER_SIZE];
	char 	sDataCollectLog[MAX_STRING_LENGTH];
	char    sDataEnv_var[MAX_ENV_STR_LEN];
	char 	local_ip[INET_ADDRSTRLEN];

	char    svrConnStartTime[ND_TIME_MAX_LEN] = {0,};
        char    svrConnEndTime[ND_TIME_MAX_LEN] = {0,};
        char    svrConnRstTpCode [4] = {0,};
        char    svrConnFailRsnCode [4] = {0,};
        char    agtNo[16] = {0,};
        char    agtConnFormTpCode[4] = {0,};
        char    agtAuthNo[ND_AGTAUTHNO_MAX_LEN] = {0,};
        char    portNo[8] = {0,};
        char    userIp[ND_SOURCEIP_MAX_LEN] = {0,};
        char    securStepNo[ND_SECUR_STEP_NO_MAX_LEN] = {0,};
        char    svrConnSessKey[ND_UUID_LENGTH] = {0,};
        char    connAcctId[ND_SYSACCOUNT_MAX_LEN] = {0,};
        char    pamAgtAuthNo[ND_AGTAUTHNO_MAX_LEN] = {0,};
        char    userNo[18] = {0,};
        char    pamCertDtlCode[4] = {0,};

        char    certTpCode[ND_CERT_TP_CODE_MAX_LEN] = {0,};
        char    certAppTpCode[ND_CERT_APP_TP_CODE_MAX_LEN] = {0,};
        char    certSucesFailYn[ND_CERT_APP_SUCES_FAIL_YN_MAX_LEN] = {0,};
        char    certStepSeqNo[ND_CERT_STEP_SEQ_NO_MAX_LEN] = {0,};

	
	/*
                // get pam config
        */
	char *user_shell = NULL;

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
                sDataHomeDir = strdup(PRODUCT_NM);

	if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

        getpamconf (&pam_conf);
        if (pam_conf.pam_operate_mode != MODE_ON)
                return PAM_SUCCESS;

	struct _msg_header_      header = {
        	.iMsgVer     		= 0,
        	.iMsgTotalSize  	= 0

	};

	header.iMsgType = 0;
        header.iMsgCode = PAM_AGT_AUTH_CODE;

	char *agent_id = get_value_as_string(getPamRuleFilePath( sDataHomeDir), "agentId");

	g_nDataSshPort = get_ssh_listening_port();

	if (g_sConfFilePath == NULL )
		g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

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

	
	/*
		// get user session info
	*/
	get_user_info(&user_info, pamh);

	/*
		// check os login result
	*/
	if (user_info.login_status != 0) // success 0, failed 1
	{
		nd_log (NDLOG_INF, "Login attempt failed for system account %s.",user_info.username);
		//pam_syslog (pamh, LOG_ERR, "pam_sm_authenticate -- login failed");
		return PAM_AUTH_ERR;
	}

	/*
		//
	*/
	// agtNo
        snprintf (agtNo, sizeof (agtNo), "%s", agent_id ? agent_id : "");
	
        // agtConnFormTpCode, // agtAuthNo (ndshell), // portNo, // usrIp

        // securStepNo
        snprintf (securStepNo, sizeof (securStepNo), "%s", PAM_SECUR_STEP_PAM);

        // svrConnSessKey
        snprintf (svrConnSessKey, sizeof (svrConnSessKey), "%s", uuid_str);

        // connAcctId, // userNo

        // pamCertDtlCode
        snprintf (pamCertDtlCode, sizeof (pamCertDtlCode), "%s", PAM_LOGIN);
		
	/*
		 // get login type (su? terminal, console)
	*/
	SessionInfo *info = NULL;

	const char *tty = get_pam_item_str(pamh, PAM_TTY);
        if (tty && strstr(tty, "ssh")) {
		
                info = get_ssh_session_info(pamh);

		// agtConnFormTpCode
                snprintf (agtConnFormTpCode, sizeof (agtConnFormTpCode), "%s", (user_info->type == 1)? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);

		// userIp
		snprintf (userIp, sizeof (userIp), "%s", info->remote_host);

		// connAcctId
        	snprintf (connAcctId, sizeof (connAcctId), "%s", user_info->current_user);

		retval = nd_pam_authenticate_user(uuid_str, info, pamh);
                if (retval != PAM_SUCCESS)
                {
                        return retval;
                }


        } else if (tty && strstr(tty, "pts")) {
	
		//parse_ssh_connection(pamh);	
                info = get_su_session_info(pamh);
		// agtConnFormTpCode
                snprintf (agtConnFormTpCode, sizeof (agtConnFormTpCode), "%s", (user_info->type == 1)? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);
		
		// userIp
		snprintf (userIp, sizeof (userIp), "%s", info->remote_host);

		// connAcctId
                snprintf (connAcctId, sizeof (connAcctId), "%s", user_info->current_user);

		isSuSession = true;

		/*
		const char *connectipaddr = pam_getenv(pamh, "HIWARE_SSH_CLIENT_IP");
		if (!connectipaddr)
			syslog (LOG_ERR, "SU : GET CONNECT IP :%s", connectipaddr);
		

		syslog (LOG_ERR, "check_pam_policy BEFOR (%s/%s", info->target_user, info->current_user);
		*/
		if (strcmp (info->remote_host, "localhost") == 0 )
		{
			pid_t parent_pid = getppid();
                	const char* parent_clientIp = read_env_variable(parent_pid, "HIWARE_SSH_CLIENT_IP");

			if (parent_clientIp != NULL )		{
				strcpy (info->remote_host, parent_clientIp);
			}else		{
				strcpy (info->remote_host, "127.0.0.1");
			}
		}

//-------------------------------------------------------------------------------------------------------------------------

		if (check_pam_policy (getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, &pam_pri_no, &agt_auth_no, &pam_action, &pam_logging))
		{
			if (pam_action == PAM_ACT_RULE_DENY)
			{
				header.iMsgType = 0;

				//svrConnFailRsnCode
				snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "14");
				// svrConnRstTpCode
				snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);

				if (pam_logging == LOGGING_ON) // 1
				{
					logitem =  create_archive_log ("", "", "", "", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host,PAM_SECUR_STEP_PAM,
									uuid_str, info->current_user, "", agt_auth_no, agent_id, PAM_LOGIN, PAM_CERT_DTL_AUTH_PAM_RULE ,"","","","");

					nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
				}

				retval = PAM_PERM_DENIED;
				goto pam_sm_auth_ex;
			}
			else
			{
				bRetPamPolicy = true;
				retval = PAM_SUCCESS;
			}
		}

		snprintf (pamAgtAuthNo, sizeof (pamAgtAuthNo), "%s", pamAgtAuthNo ? pamAgtAuthNo : "");

#ifdef _SUPP_DATE_
		time_t current_time = time(NULL);
		struct tm *tm_info = localtime(&current_time);
		int current_wday = tm_info->tm_wday == 0 ? 7 : tm_info->tm_wday; // Adjust for Sunday being 7

		if (is_pam_user_ndshell(pamh) &&
			validate_json_sampolicy(getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, current_time, current_wday) == 1)
#else //_SUPP_DATE_
		if (is_pam_user_ndshell(pamh) &&
			validate_json_sampolicy_without_date(getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, &ndshell_agtAuthNo, &sam_action, &sam_logging) == 1)
#endif //_SUPP_DATE_
		{

			if (sam_action == PAM_ACT_RULE_DENY )
			{
				//SVR_CONN_FAIL_RSN_CODE : 미인가 계정 접속
				// code 14
				snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), "14");

				// svrConnRstTpCode
				snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
				header.iMsgType = 0;

				retval = PAM_PERM_DENIED;
				goto pam_sm_auth_ex;
			}
			else
			{
				bRetSamPolicy = true;

				retval = PAM_SUCCESS;
			}
		}

		snprintf (agtAuthNo, sizeof (agtAuthNo), "%s", ndshell_agtAuthNo ? ndshell_agtAuthNo : "");

		if (bRetPamPolicy == false && bRetSamPolicy == false)
			return PAM_SUCCESS;

		

#ifdef _DEF_BLOCK_MODE_

		if (check_pam_policy (getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, &pri_no, &agt_auth_no, &action, &logging))
		{
			bool isNdShell = is_pam_user_ndshell(pamh);
			if (isNdShell == true )
                        {
                        	time_t current_time = time(NULL);
                                struct tm *tm_info = localtime(&current_time);
                                int current_wday = tm_info->tm_wday == 0 ? 7 : tm_info->tm_wday; // Adjust for Sunday being 7
#ifdef _SUPP_DATE_
				retval = validate_json_sampolicy(getPamRuleFilePath( sDataHomeDir), info->remote_host, info->target_user, current_time, current_wday);
#else //_SUPP_DATE_
				retval = validate_json_sampolicy_without_date(getPamRuleFilePath( sDataHomeDir), info->remote_host, info->target_user, &ndshell_agtAuthNo, &sam_action, &sam_logging );
#endif //_SUPP_DATE_
				if (retval == 1)        {
					syslog (LOG_ERR, "Access granted: SAMPolicy matched.");
					if (action != PAM_USER_RULE_ACT_DENY)
					{
						if (logging == LOGGING_ON) // 1
						{
							logitem =  create_archive_log ("", "", "", "", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host,PAM_SECUR_STEP_NDSHELL,
											uuid_str, info->target_user, info->current_user,agt_auth_no, agent_id, PAM_SU, PAM_CERT_DTL_AUTH_SAM_RULE ,"","","","");

							nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
						}

						retval = PAM_SUCCESS;
						goto pam_sm_auth_ex;

					}

					else
					{
						if (logging == LOGGING_ON) // 1
						{
							//SVR_CONN_FAIL_RSN_CODE : 미인가 계정 접속
                                                        // code 14
							logitem =  create_archive_log ("", "", PAM_AUTH_FAIL, "14", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host,PAM_SECUR_STEP_NDSHELL,
                                                                                        uuid_str, info->target_user, info->current_user,agt_auth_no, agent_id, PAM_SU, PAM_CERT_DTL_AUTH_SAM_RULE ,"","","","");

							nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
						}

						retval = PAM_PERM_DENIED;
						goto pam_sm_auth_ex;
					}
				}

				else
				{
					if (logging == LOGGING_ON) // 1
					{
						//SVR_CONN_FAIL_RSN_CODE : 미인가 계정 접속
                                                        // code 14
						logitem =  create_archive_log ("", "", PAM_AUTH_FAIL, "14", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host, PAM_SECUR_STEP_NDSHELL,
										uuid_str, info->target_user, info->current_user, agt_auth_no, agent_id, PAM_SU, PAM_CERT_DTL_AUTH_PAM_RULE ,"","","","");
						
						nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
					}

					retval =  PAM_PERM_DENIED;
					goto pam_sm_auth_ex;

				}
			}	

			if (logging == LOGGING_ON) // 1
			{

				logitem =  create_archive_log ("", "", "", "", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host,PAM_SECUR_STEP_PAM,
                                                               uuid_str, info->target_user, info->current_user, agt_auth_no, agent_id, PAM_SU, PAM_CERT_DTL_AUTH_PAM_RULE ,"","","","");

                                nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);

			}

			retval = PAM_SUCCESS;
			goto pam_sm_auth_ex;

		}

		else
		{
			if (logging == LOGGING_ON) // 1
			{
				logitem =  create_archive_log ("", "", "", "", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host,PAM_SECUR_STEP_PAM,
								uuid_str, info->current_user, "", agt_auth_no, agent_id, PAM_LOGIN, PAM_CERT_DTL_AUTH_PAM_RULE ,"","","","");

				nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
			}

			retval = PAM_PERM_DENIED;
			goto pam_sm_auth_ex;
		}

		//-------------------------------------------------------------------------------------------------------------------------		
#endif //_DEF_BLOCK_MODE_

        }else
	{
		//console
		info = get_console_session_info(pamh);

		// agtConnFormTpCode
                snprintf (agtConnFormTpCode, sizeof (agtConnFormTpCode), "%s", (user_info->type == 1)? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);

		// userIp
                snprintf (userIp, sizeof (userIp), "%s", info->remote_host);

		// connAcctId
                snprintf (connAcctId, sizeof (connAcctId), "%s", user_info->current_user);

		const char *service;
		 retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
		if (retval != PAM_SUCCESS) {
			return retval;
		}

		/*
			// Proceed with processing if the entered command is either 'su' or 'su -l'. Detect both cases based on the usage of the 'su' command.
		*/
		if (service != NULL && (strcmp (service, STR_SU) == 0 || strcmp (service, STR_SUL) == 0))
		{

			if (check_pam_policy (getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, &pam_pri_no, &agt_auth_no, &pam_action, &pam_logging))
                	{
                        	bool isNdShell = is_pam_user_ndshell(pamh);
                        	if (isNdShell == true )
                        	{
					retval = validate_json_sampolicy_without_date(getPamRuleFilePath( sDataHomeDir), info->remote_host, info->target_user, &ndshell_agtAuthNo, &sam_action, &sam_logging);


					if (retval == 1)        {
						if (pam_action != PAM_USER_RULE_ACT_DENY)
						{
							if (pam_logging == LOGGING_ON) // 1
							{
								logitem =  create_archive_log ("", "", "", "", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host,PAM_SECUR_STEP_NDSHELL,
                                                                                        uuid_str, info->target_user, info->current_user, agt_auth_no, agent_id, PAM_SU, PAM_CERT_DTL_AUTH_SAM_RULE ,"","","","");

								nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
							}

							retval = PAM_SUCCESS;
							goto pam_sm_auth_ex;

						}

						else
						{
							if (pam_logging == LOGGING_ON) // 1
							{

								//SVR_CONN_FAIL_RSN_CODE : 미인가 계정 접속
								// code 14
								logitem =  create_archive_log ("", "", PAM_AUTH_FAIL, "14", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host,PAM_SECUR_STEP_NDSHELL,
												uuid_str, info->target_user, info->current_user, agt_auth_no, agent_id, PAM_SU, PAM_CERT_DTL_AUTH_SAM_RULE ,"","","","");
								
								nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
							}

							retval = PAM_PERM_DENIED;
							goto pam_sm_auth_ex;

						}
					}
					else
					{
						if (pam_logging == LOGGING_ON) // 1
						{
							//SVR_CONN_FAIL_RSN_CODE : 미인가 계정 접속
                                                        // code 14
                                                	logitem =  create_archive_log ("", "", PAM_AUTH_FAIL, "14", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host, PAM_SECUR_STEP_NDSHELL,
                                                                                uuid_str, info->target_user, info->current_user, agt_auth_no, agent_id, PAM_SU, PAM_CERT_DTL_AUTH_PAM_RULE ,"","","","");


							nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
						}
						retval =  PAM_PERM_DENIED;
						goto pam_sm_auth_ex;
					}
				}
				
				if (pam_logging == LOGGING_ON) // 1
				{
					logitem =  create_archive_log ("", "", "", "", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host,PAM_SECUR_STEP_PAM,
                                                                        uuid_str, info->target_user, info->current_user, agt_auth_no, agent_id, PAM_SU, PAM_CERT_DTL_AUTH_PAM_RULE ,"","","","");					


					nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
				}

				retval = PAM_SUCCESS;
				goto pam_sm_auth_ex;
			}

			else
			{
				if (pam_logging == LOGGING_ON) // 1
				{
					logitem =  create_archive_log ("", "", "", "", agent_id, PAM_CONN_BYPASS, ndshell_agtAuthNo, "", info->remote_host,PAM_SECUR_STEP_PAM,
                                                                uuid_str, info->current_user, "", agt_auth_no, agent_id, PAM_LOGIN, PAM_CERT_DTL_AUTH_PAM_RULE ,"","","","");


					nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
				}
				retval = PAM_PERM_DENIED;
				goto pam_sm_auth_ex;
			}
		}
		else
		{
			retval = nd_pam_authenticate_user(uuid_str, info, pamh);
			if (retval != PAM_SUCCESS)
			{
				return retval;
			}

		}

	} 
	

 pam_sm_auth_ex:

	if (info)
  	     	free_session_info(info);

	free ((void*)agent_id);

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

	//return PAM_SUCCESS;
	syslog (LOG_ERR, "pam_sm_open_session -001");

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
        if (sDataHomeDir == NULL)
                sDataHomeDir = strdup(PRODUCT_NM);

        if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	struct  st_pam_conf             pam_conf;

	

	/*
                // get pam config
        */
        getpamconf (&pam_conf);
        if (pam_conf.pam_operate_mode != MODE_ON)
                return PAM_SUCCESS;

	syslog (LOG_ERR, "pam_sm_open_session -002");



	bool bIsConsole = false;

	system("clear");
	const char *tty = get_pam_item_str(pamh, PAM_TTY);
        if (tty && strstr(tty, "ssh") || tty && strstr(tty, "pts")) {

		bIsConsole = false;
	}else
		bIsConsole = true;

	syslog (LOG_ERR, "pam_sm_open_session -003");
	parse_ssh_connection(pamh, bIsConsole);

	syslog (LOG_ERR, "pam_sm_open_session -004");

	return PAM_SUCCESS;
#ifdef _OLD_SRC_	
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
	struct _archive_log                             *logitem;

	pam_client_info info ;

	struct _msg_header_             header = {

		.iMsgTotalSize  = 0
	};

	g_nDataSshPort = get_current_ssh_port(pamh);

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
                sDataHomeDir = strdup(PRODUCT_NM);

	if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	//setAgentId("5");

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

#ifdef _OPENSESSION_SUPP

	header.iMsgType = isSuSession ? PACK_MSG_TYPE_SU_SESSION : PACK_MSG_TYPE_SSH_SESSION;
    	header.iMsgCode = PACK_MSG_CODE_SESSION_OPEN;

	logitem =  create_archive_log ("NDAPAM-SESSION", agent_id, agt_auth_no, session_id, "", (isConsole == true)? "2" : "1",
                                                        ip_address, "NDAPAM-SESSION-CREATE", username, "", "", "New session created.", true);

	nd_pam_archive_log(header, *logitem, (char*) sDataHomeDir);

	free_archive_log(logitem);
#endif //_OPENSESSION_SUPP
	free(session_id);
	return PAM_SUCCESS;
#endif //_OLD_SRC_
}

/*
        //Function Definition of Linux PAM Module [pam_sm_close_session]
*/
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) 	{

	(void)argc;
	(void)argv;
	(void)flags;

	char agt_auth_Number[4] = {0,};
	bool isConsole		= NULL;
	SessionInfo *info = NULL;
	struct _archive_log          *logitem;
	 struct  st_pam_conf         pam_conf;

        struct _msg_header_ header = {

                .iMsgTotalSize  = 0
        };

	/*
                // get pam config
        */
        getpamconf (&pam_conf);
        if (pam_conf.pam_operate_mode != MODE_ON)
                return PAM_SUCCESS;

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
        if (sDataHomeDir == NULL)
                sDataHomeDir = strdup(PRODUCT_NM);

        if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	g_sDataHiwareUserNumber = pam_getenv(pamh, "HIWARE_USER_NUMBER");
	if (g_sDataHiwareUserNumber == NULL)
		g_sDataHiwareUserNumber = getenv("HIWARE_USER_NUMBER");

	int pri_no, action, logging;
        char *agt_auth_no;
        const char *agent_id = get_value_as_string(getPamRuleFilePath( sDataHomeDir), "agentId");
	const char *sessionkey = pam_getenv(pamh, ENV_HIWARE_SESSIONKEY);

	 g_nDataSshPort = get_ssh_listening_port();

	if (agent_id == NULL )
	{
		syslog (LOG_ERR, "pam_sm_close_session agent_id NULL");
	}

	if (sessionkey == NULL )
	{
		sessionkey = getenv (ENV_HIWARE_SESSIONKEY);
	}


	// Determine session type and call corresponding function
        const char *tty = get_pam_item_str(pamh, PAM_TTY);
        if (tty && strstr(tty, "ssh")) {
                info = get_ssh_session_info(pamh);
        } else if (tty && strstr(tty, "pts")) {
                info = get_su_session_info(pamh);
        } else {
                info = get_console_session_info(pamh);
        }


	header.iMsgType = 0;//isSuSession ? PACK_MSG_TYPE_SU_SESSION : PACK_MSG_TYPE_SSH_SESSION;
        header.iMsgCode = PAM_AGT_AUTH_CODE;

	check_pam_policy (getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, &pri_no, &agt_auth_no, &action, &logging);

	if (logging == LOGGING_ON) // 1
	{
#ifdef _ETC_LOG_SET
		logitem =  create_archive_log (PAM_LOGOUT, agent_id, (agt_auth_no)?agt_auth_no:"", sessionkey, "", (info->remote_host == 1)? "2" : "1",
								info->remote_host, "NDAPAM-SESSION-TERMINATE", info->current_user, "", "", "00", PAM_AUTH_FAIL,"","","","");

		nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
		free_archive_log(logitem);
#endif //_ETC_LOG_SET
	}


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
