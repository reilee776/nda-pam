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

char * g_sDataProductNm;

char * g_sDataRootDir;
int g_nDataSshPort = 0;

char * g_sConfFilePath;

char g_sDataAgentId[2];
/////////
//static const char *current_user;

pthread_mutex_t session_id_mutex;

/*
*/
#define PAM_HIWARE_SSH_SERVER_IP        "HIWARE_SSH_CLIENT_IP"
#define PAM_HIWARE_SSH_SERVER_PORT      "HIWARE_SSH_SERVER_PORT"
#define PAM_HIWARE_SSH_CLIENT_IP        "HIWARE_SSH_CLIENT_IP"
#define PAM_HIWARE_SSH_CLIENT_PORT      "HIWARE_SSH_CLIENT_PORT"



typedef struct {
        bool pamPolicyValid;
        bool samPolicyValid;

        int pam_pri_no;
        int pam_action;
        int pam_logging;
        char* pam_agtAuthNo;

        int sam_pri_no;
        int sam_action;
        int sam_logging;
        char* sam_agtAuthNo;
} PolicyValidationResult;


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

struct st_log_level
nd_log_level[] = {
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
		return -1; // failed open file
	}

	char line[MAX_LINE_LENGTH];
	while (fgets(line, sizeof(line), file) != NULL) {
		// Remove the newline character at the end of the line.
		line[strcspn(line, "\n")] = 0;

		// Practice키- Separate values
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
	const char *current_user;
	const char *switch_user;
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


PolicyValidationResult validate_access_policies (const char* rulePath, const SessionInfo* userInfo, pam_handle_t* pamh)
{
	// Initialize result structure
	PolicyValidationResult result = {false, false, 0, 0, NULL};

	// Check PAM policy
	if (check_pam_policy(rulePath, 
				userInfo->remote_host, 
				userInfo->current_user, 
				&result.pam_pri_no, 
				&result.pam_agtAuthNo , 
				&result.pam_action, 
				&result.pam_logging)) 	{
		result.pamPolicyValid = true;
	} else {
		result.pamPolicyValid = false;
	}	

#ifdef _SUPP_DATE_
	// Policy validation with date support
	time_t current_time = time(NULL);
	struct tm *tm_info = localtime(&current_time);
	int current_wday = tm_info->tm_wday == 0 ? 7 : tm_info->tm_wday; // Adjust Sunday to 7

	if (is_pam_user_ndshell(pamh) &&
		validate_json_sampolicy(getPamRuleFilePath(configPath), 
					userInfo->remote_host, 
					userInfo->current_user, 
					current_time, 
					current_wday) == 1) {
		result.samPolicyValid = true;
	}
#else	
	// Policy validation without date support
	if (is_pam_user_ndshell(pamh) &&
        	validate_json_sampolicy_without_date(Path(rulePath), 
                                             userInfo->remote_host, 
                                             userInfo->current_user, 
                                             &result.sam_agtAuthNo, 
                                             &result.sam_action, 
                                             &result.sam_logging) == 1) {
        	result.samPolicyValid = true;
	}
#endif //_SUPP_DATE_

	return result;
}


int nd_pam_authenticate_user (char * uuid_str, /*struct pam_user_info*/SessionInfo * user_info, pam_handle_t * pamh)
{
	int authsvr_port = 0, retval = 0;
	int pam_pri_no, pam_action, pam_logging, sam_pri_no, sam_action, sam_logging;

	bool 	bRetPamPolicy = false, bRetSamPolicy = false, bHiwareAuthRet = false, bIsLogging = false;

	char  	*hiwareTwoFactData = NULL;
	char 	sTwoFactString[128];
	char    sDataEnv_var[MAX_ENV_STR_LEN];

	char    svrConnStartTime[ND_TIME_MAX_LEN] = {0,}, svrConnEndTime[ND_TIME_MAX_LEN] = {0,}, svrConnRstTpCode [4] = {0,}, svrConnFailRsnCode [4] = {0,}, agtNo[16] = {0,},
        	agtConnFormTpCode[4] = {0,},  agtAuthNo[ND_AGTAUTHNO_MAX_LEN] = {0,}, portNo[8] = {0,}, userIp[ND_SOURCEIP_MAX_LEN] = {0,}, securStepNo[ND_SECUR_STEP_NO_MAX_LEN] = {0,},
        	svrConnSessKey[ND_UUID_LENGTH] = {0,}, connAcctId[ND_SYSACCOUNT_MAX_LEN] = {0,}, switchAcctId[ND_SYSACCOUNT_MAX_LEN] = {0,}, pamAgtAuthNo[ND_AGTAUTHNO_MAX_LEN] = {0,},
        	userNo[18] = {0,}, pamCertDtlCode[4] = {0,}, pamCertDtlAuthCode[4] = {0,};

        char    certTpCode[ND_CERT_TP_CODE_MAX_LEN] = {0,}, certAppTpCode[ND_CERT_APP_TP_CODE_MAX_LEN] = {0,}, certSucesFailYn[ND_CERT_APP_SUCES_FAIL_YN_MAX_LEN] = {0,}, certStepSeqNo[ND_CERT_STEP_SEQ_NO_MAX_LEN] = {0,};

        char *agt_auth_no, *ndshell_agtAuthNo, *agent_id;


	sprintf (sTwoFactString, "OTP(One-Time Password): ");
	sprintf (pamCertDtlAuthCode, "%s", PAM_CERT_DTL_AUTH_OS);
	snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);

	struct _archive_log 			*logitem;
	struct st_hiauth_input_data    		*hiauth_input_data;
	st_hiauth_twofact_login_result		hi_twofact_ret;
	struct st_hiauth_hiware_login_result 	hi_hiwareauth_ret;

	struct _msg_header_   header = {
        	.iMsgVer        = 0,
        	.iMsgTotalSize  = 0,
		.iMsgType 	= 0,
		.iMsgCode 	= 0
	};

	//
	///
	nd_log (NDLOG_TRC, "start function - nd_pam_authenticate_user");

	const char *sDataHomeDir = get_env_variable (pamh, ENV_HIWARE_HOME);
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

	//
	///
	nd_log (NDLOG_TRC, "====================================================================");
	nd_log (NDLOG_TRC, "[reading configuration information]");
	nd_log (NDLOG_TRC, " - auth_server_ip : [%s]",auth_server_ip);
	nd_log (NDLOG_TRC, " - auth_server_port : [%s]", auth_server_port);
	nd_log (NDLOG_TRC, " - authsvr_emergency_act : [%s]",authsvr_emergency_act);
	nd_log (NDLOG_TRC, "--------------------------------------------------------------------");

	/*
		// convert server port
	*/
	authsvr_port = auth_server_port ? atoi(auth_server_port) : PAM_HIAUTH_DEFAULT_PORT;

	//
	///
	nd_log (NDLOG_TRC, "Checking connection to the API server.- server ip:[%s], server port:[%d]", auth_server_ip, authsvr_port);


	/*
		// server connect check
	*/
	bool bisAlive_server = check_server_connection(auth_server_ip, authsvr_port);
	if (bisAlive_server != true )
	{
		for (int i = 0 ; i < 3; i++ )		{

			bisAlive_server = check_server_connection(auth_server_ip, authsvr_port);
			if (bisAlive_server)	{
				sleep(3);
				break;
			}

			nd_log (NDLOG_TRC, "check_server_connection :: retry cnt (%d/3)", i);
		}
	}


	//
	///
	nd_log (NDLOG_TRC, "Checking connection to the API server. bisAlive_server = %d",bisAlive_server);

	agent_id = get_value_as_string(getPamRuleFilePath( sDataHomeDir), "agentId");

	if (agent_id == NULL )
		retval = PAM_AUTH_ERR;

	nd_log (NDLOG_TRC, "get_value_as_string:: %s", agent_id);

	snprintf(agtNo, sizeof(agtNo), "%s", agent_id ? agent_id : "");
	snprintf(agtConnFormTpCode, sizeof(agtConnFormTpCode), "%s", (user_info->type == 1) ? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);
	snprintf(userIp, sizeof(userIp), "%s", user_info->remote_host);
	snprintf(securStepNo, sizeof(securStepNo), "%s", PAM_SECUR_STEP_PAM);
	snprintf(svrConnSessKey, sizeof(svrConnSessKey), "%s", uuid_str);
	snprintf(connAcctId, sizeof(connAcctId), "%s", user_info->current_user);
	snprintf(pamCertDtlCode, sizeof(pamCertDtlCode), "%s", PAM_LOGIN);

	const char * _agtSvrAbleYn = get_value_as_string (getPamRuleFilePath( sDataHomeDir), "agtSvrAbleYn");
	const char * _pamCertYn    = get_value_as_string (getPamRuleFilePath( sDataHomeDir), "pamCertYn");
	PolicyValidationResult result = validate_access_policies (getPamRuleFilePath( sDataHomeDir), user_info, pamh );

	nd_log (NDLOG_TRC, "_agtSvrAbleYn = %s/ _pamCertYn = %s", _agtSvrAbleYn, _pamCertYn);

	if (strcmp (_agtSvrAbleYn, "1") == 0 && result.samPolicyValid == true ) 
	{
		bIsLogging = result.sam_logging;

		if (sam_action == PAM_ACT_RULE_DENY)
		{
			nd_log (NDLOG_TRC, "new test -002");
			if (bisAlive_server == false)
			{
				snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_EMERGC_FAILED);
			}
			else
			{
				snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_NORMAL_FAILED);
			}

			snprintf (svrConnFailRsnCode,   sizeof (svrConnFailRsnCode),    PAM_SVR_FAIL_UNAUTH_ACCESS);
                        snprintf (pamCertDtlAuthCode,   sizeof (pamCertDtlAuthCode),    "%s", PAM_CERT_DTL_AUTH_SAM_RULE);
			snprintf (svrConnRstTpCode , 	sizeof (svrConnRstTpCode), 	"%s", PAM_AUTH_FAIL);

                        //
                        ///
                        nd_log (NDLOG_INF, "Connection is blocked as the sam policy action setting is set to block.[ip addr:%s/account:%s]", user_info->remote_host, user_info->current_user);

                        retval = PAM_PERM_DENIED;
                        goto nd_pam_authenticate_user;
		}

		else
		{
			nd_log (NDLOG_TRC, "new test -003");
			memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));
                        snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_NOT_CONNECTAPI_FORMAT, "BYPASS");
                        pam_putenv(pamh, sDataEnv_var);


			snprintf(svrConnRstTpCode, sizeof(svrConnRstTpCode), "%s", PAM_SVR_CONN_RST_TP_CODE_NORMAL_SUCCESS);
                        bRetSamPolicy = true;

                        //
                        ///
                        nd_log (NDLOG_INF, "Connection is allowed as the sam policy action setting is set to allow.[ip addr:%s/account:%s]", user_info->remote_host, user_info->current_user);

                        retval = PAM_SUCCESS;
		}

		snprintf (agtAuthNo, sizeof (agtAuthNo), "%s", result.sam_agtAuthNo ? result.sam_agtAuthNo : "");
	}

	nd_log (NDLOG_TRC, "new test -004");

	if (strcmp (_pamCertYn, "1") == 0 && result.pamPolicyValid == true  )		
	{
		nd_log (NDLOG_TRC, "new test -005");
		bIsLogging = result.pam_logging;

		if ( pam_action == PAM_ACT_RULE_DENY )
		{

			nd_log (NDLOG_TRC, "new test -006");
			if (bisAlive_server == false)
                        {
				snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_EMERGC_FAILED);
			}

			else
			{
				snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_NORMAL_FAILED);
			}

			snprintf (svrConnFailRsnCode,   sizeof (svrConnFailRsnCode),    PAM_SVR_FAIL_UNAUTH_ACCESS);
			snprintf (pamCertDtlAuthCode,   sizeof(pamCertDtlAuthCode),     "%s", PAM_CERT_DTL_AUTH_PAM_RULE);

			nd_log (NDLOG_INF, "Connection is blocked as the pam policy action setting is set to block.[ip addr:%s/account:%s]", user_info->remote_host, user_info->current_user);

			retval = PAM_PERM_DENIED;
			goto nd_pam_authenticate_user;
		}

		else
		{
			nd_log (NDLOG_TRC, "new test -007");
			memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));
                        snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_NOT_CONNECTAPI_FORMAT, "BYPASS");
                        pam_putenv(pamh, sDataEnv_var);

			retval = PAM_SUCCESS;

			if (bisAlive_server == false)
                        {
				nd_log (NDLOG_TRC, "new test -007-1");
                                snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_EMERGC_SUCCESS);
				goto nd_pam_authenticate_user;
                        }

                        else
                        {
				nd_log (NDLOG_TRC, "new test -007-2");
                                snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_NORMAL_SUCCESS);
                        }

                        bRetPamPolicy = true;

                        //
                        ///
                        nd_log (NDLOG_INF, "Connection is allowed as the pam policy action setting is set to allow.[ip addr:%s/account:%s]", user_info->remote_host, user_info->current_user);

                        retval = PAM_SUCCESS;
		}

		snprintf (pamAgtAuthNo, sizeof (pamAgtAuthNo), "%s", result.pam_agtAuthNo ? result.pam_agtAuthNo : "");
		
	}

	nd_log (NDLOG_TRC, "pamPolicyValid = %d/ samPolicyValid = %d", result.pamPolicyValid, result.samPolicyValid);

	nd_log (NDLOG_TRC, "new test -008");
	if (result.pamPolicyValid == false && result.samPolicyValid == false)
	{
		nd_log (NDLOG_TRC, "new test -009");
		if (bisAlive_server == false)
                {
			if (strcmp (authsvr_emergency_act, SET_MODE_BYPASS) == 0 )      {
				snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_EMERGC_SUCCESS);
				retval = PAM_SUCCESS;
			}

			else
			{
				snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_EMERGC_FAILED);
				snprintf (svrConnFailRsnCode,   sizeof (svrConnFailRsnCode),    PAM_SVR_FAIL_HIWARE_DOWNTIME);
				retval = PAM_PERM_DENIED;
			}

		}
		else
		{
			if (strcmp (authsvr_emergency_act, SET_MODE_BYPASS) == 0 )      {
                                snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_NORMAL_SUCCESS);
                                retval = PAM_SUCCESS;
                        }

                        else
                        {
                                snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_SVR_CONN_RST_TP_CODE_NORMAL_FAILED);
				snprintf (svrConnFailRsnCode,   sizeof (svrConnFailRsnCode),    PAM_SVR_FAIL_HIWARE_DOWNTIME);
                                retval = PAM_PERM_DENIED;
                        }

		}

		snprintf(pamCertDtlAuthCode,    sizeof(pamCertDtlAuthCode),     "%s", PAM_CERT_DTL_AUTH_OS);
		//
                ///
                nd_log (NDLOG_INF, "Does not comply with the policy - Accepting login without performing additional actions as per the policy.(%s/%s)",user_info->remote_host, user_info->current_user);

                goto nd_pam_authenticate_user; //return PAM_SUCCESS;
	}
	
	nd_log (NDLOG_TRC, "new test -010");
	//
        ///
        nd_log (NDLOG_TRC, "checking pam/sam policy Complete.");
	
	for (int i = 0 ; i < 3 ; i ++ )
	{
		if (bHiwareAuthRet == true )
			break;

		hiauth_input_data = OperateHiAuth(pamh);
		if ((hiauth_input_data->sHiAuthId == NULL || strlen (hiauth_input_data->sHiAuthPw) <= 0)  ||
			(hiauth_input_data->sHiAuthPw == NULL || strlen (hiauth_input_data->sHiAuthPw) <= 0))
		{
			nd_log(NDLOG_ERR, "Authentication failed: Invalid input. Attempt count: %d/3",i);			

			continue;
		}
		else
		{
			bHiwareAuthRet = true;
		}
	}

	if (bHiwareAuthRet == false)
	{
		snprintf (svrConnFailRsnCode, 	sizeof (svrConnFailRsnCode), 	PAM_SVR_FAIL_HI_AUTH_FAIL);
		snprintf (svrConnRstTpCode , 	sizeof (svrConnRstTpCode), 	"%s", PAM_AUTH_FAIL);
		snprintf (pamCertDtlAuthCode, 	sizeof (pamCertDtlAuthCode), 	"%s", PAM_CERT_DTL_AUTH_HIWAREAUTH);

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
	
	//
	///
	nd_log (NDLOG_TRC, "Starting the authentication process with the API server for HIWARE authentication.");

	snprintf (pamCertDtlAuthCode, sizeof (pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_HIWAREAUTH );
	retval = requestHiwareAuthToApiServer(hiauth_input_data->sHiAuthId, hiauth_input_data->sHiAuthPw, agt_auth_no, &hi_hiwareauth_ret);
	if (retval != HI_AUTH_RET_SUCCEED || hi_hiwareauth_ret.ret != 200 )
	{
                snprintf (svrConnFailRsnCode, 	sizeof (svrConnFailRsnCode), 	PAM_SVR_FAIL_HI_AUTH_FAIL);
                snprintf (svrConnRstTpCode , 	sizeof (svrConnRstTpCode), 	"%s", PAM_AUTH_FAIL);
                snprintf (pamCertDtlAuthCode, 	sizeof (pamCertDtlAuthCode), 	"%s", PAM_CERT_DTL_AUTH_HIWAREAUTH);

		//
		///
		nd_log (NDLOG_ERR, "Failed to start the authentication process with the API server for HIWARE authentication. [account:%s/ hiware account:%s/ retcode:%d]", user_info->current_user, hiauth_input_data->sHiAuthId, hi_hiwareauth_ret);

		retval = PAM_AUTH_ERR;
		goto nd_pam_authenticate_user;
	}


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
                	snprintf (svrConnFailRsnCode, 	sizeof (svrConnFailRsnCode), 	PAM_SVR_FAIL_TF_AUTH_FAIL);
                	snprintf (svrConnRstTpCode , 	sizeof (svrConnRstTpCode), 	"%s", PAM_AUTH_FAIL);
                	snprintf (pamCertDtlAuthCode, 	sizeof (pamCertDtlAuthCode), 	"%s", PAM_CERT_DTL_AUTH_TWOFACT);

			retval = PAM_AUTH_ERR;
			goto nd_pam_authenticate_user;
		}

		snprintf ( svrConnRstTpCode, 	sizeof(svrConnRstTpCode), 	"%s", PAM_AUTH_SUCCESS);
		snprintf ( certTpCode,          sizeof (certTpCode),            "%s", hi_twofact_ret.certTpCode);
                snprintf ( certAppTpCode,       sizeof (certAppTpCode),         "%s", hi_twofact_ret.certAppTpCode);
                snprintf ( certSucesFailYn,     sizeof (certSucesFailYn),       "%s", hi_twofact_ret.certSucesFailYn);
                snprintf ( certStepSeqNo,       sizeof (certStepSeqNo),         "%s", hi_twofact_ret.certStepSeqNo);

		nd_log (NDLOG_TRC, "HIWARE additional authentication task was successfully completed.");
		retval = PAM_SUCCESS;
	}
	else
	{
		if (g_sDataUserLoginResult == NULL || strcmp (g_sDataUserLoginResult, PAM_LOGIN_RESULT_FALSE) == 0 )
		{
                        snprintf (svrConnFailRsnCode, 	sizeof (svrConnFailRsnCode), PAM_SVR_FAIL_TF_AUTH_FAIL);
                	snprintf (svrConnRstTpCode , 	sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
                        snprintf (pamCertDtlAuthCode, 	sizeof (pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_TWOFACT);

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

	if (pam_logging == LOGGING_ON || bisAlive_server == false) 	{

		nd_log (NDLOG_TRC, "new test --11");
		logitem =  create_archive_log (svrConnStartTime, svrConnEndTime, svrConnRstTpCode, svrConnFailRsnCode, agtNo, agtConnFormTpCode,
						agtAuthNo, portNo, userIp, securStepNo, svrConnSessKey, connAcctId, switchAcctId, pamAgtAuthNo, userNo, pamCertDtlCode,pamCertDtlAuthCode,
						certTpCode, certAppTpCode,certSucesFailYn,certStepSeqNo);
		nd_log (NDLOG_TRC, "new test --11-1");

		nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);

		nd_log (NDLOG_TRC, "new test --11-2");
		free_archive_log(logitem);
		nd_log (NDLOG_TRC, "new test --11-3");
	}

	nd_log (NDLOG_TRC, "new test --12");

	if (agent_id)
		free (agent_id);

	nd_log (NDLOG_TRC, "new test --13");

	if (agt_auth_no)
        	free (agt_auth_no);

	nd_log (NDLOG_TRC, "new test --14");

	return retval;
}

void print_session_info(const SessionInfo *info) 	{

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
	bool 	isSuSession 	= false;
	bool    isNdShell 	= false;
	struct 	st_pam_conf	pam_conf;
	char	*uuid_str;
	struct  _archive_log   *logitem = NULL;
	char	*ndshell_agtAuthNo = NULL;
	
	bool    bRetPamPolicy = false, bRetSamPolicy = false;

	char *crypted;
	const char *encrypt_passwd;
        const char *input_passwd;
        const char *current_user;

	int 	pam_pri_no, pam_action, pam_logging, sam_action, sam_logging, login_status= 0;
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
	char    switchAcctId[ND_SYSACCOUNT_MAX_LEN] = {0,};
        char    pamAgtAuthNo[ND_AGTAUTHNO_MAX_LEN] = {0,};
        char    userNo[18] = {0,};
        char    pamCertDtlCode[4] = {0,};
	char    pamCertDtlAuthCode[4] = {0,};

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

	if (sDataHomeDir != NULL )
		g_sDataRootDir = strdup(sDataHomeDir);

	if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

        getpamconf (&pam_conf);
        if (pam_conf.pam_operate_mode != MODE_ON)
                return PAM_SUCCESS;

	struct _msg_header_      header = {
        	.iMsgVer     		= 0,
        	.iMsgTotalSize  	= 0

	};

	char *agent_id = get_value_as_string(getPamRuleFilePath( sDataHomeDir), "agentId");
	g_nDataSshPort = get_ssh_listening_port();

	if (g_sConfFilePath == NULL )
		g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	/*
		// Initialization of necessary variables for authentication tasks
	*/
	initializeAuthVariables();

        get_local_ip(local_ip, sizeof(local_ip));

	/*
		// creat new uuid
	*/	
	uuid_str = generate_uuid();

	//
	///
	nd_log (NDLOG_INF, "local ip address : [%s]", local_ip);
	nd_log (NDLOG_INF, "generate session key : [%s]", uuid_str);

	/*
		// get user session info
	*/
	//get_user_info(&user_info, pamh);

	if (pam_get_user(pamh, &current_user, NULL) == PAM_SUCCESS && current_user != NULL)      {

		//strncpy(user_info->username, current_user, sizeof(user_info->username) - 1);
		//user_info->username[sizeof(user_info->username) - 1] = '\0';
	}

	/*
                // Getting the user input password.
        */
        retval = pam_get_authtok(pamh, PAM_AUTHTOK, &input_passwd, NULL);
        if (retval != PAM_SUCCESS) {

		//
		///
                nd_log(NDLOG_ERR,"failed to get user password...[pam_get_authtok]");
                return;
        }

	/*
		// check os login result
	*/
	encrypt_passwd = get_encrypted_password_from_shadow(current_user);
        if (!encrypt_passwd )    {
		
		//
		///
		nd_log (NDLOG_ERR, "failed to get encrypted password from shadow file..(%s)", current_user);
                return;
        }

        /*
                //Calls the crypt function using the user input password (input_passwd) along with the user's password hash (user_info->encrypted_password).
        */
	crypted = crypt(input_passwd, encrypt_passwd);
	if (strcmp(crypted, encrypt_passwd) == 0)        {

		login_status = 0;
	} else          {

		login_status = 1;
	}

	if (login_status != 0) // success 0, failed 1
	{
		nd_log (NDLOG_INF, "Login attempt failed for system account %s.", current_user);
		return PAM_AUTH_ERR;
	}

	//
	///
	nd_log (NDLOG_INF, "Login attempt successful for system account. %s", current_user);

        snprintf (agtNo, sizeof (agtNo), "%s", agent_id ? agent_id : "");
        snprintf (securStepNo, sizeof (securStepNo), "%s", PAM_SECUR_STEP_PAM);
        snprintf (svrConnSessKey, sizeof (svrConnSessKey), "%s", uuid_str);
        snprintf (pamCertDtlCode, sizeof (pamCertDtlCode), "%s", PAM_LOGIN);
		
	/*
		 // get login type (su? terminal, console)
	*/
	SessionInfo *info = NULL;
	const char *tty = get_pam_item_str(pamh, PAM_TTY);
        if (tty && strstr(tty, "ssh")) {

		nd_log (NDLOG_INF, "current session type is terninal (ssh)");

                info = get_ssh_session_info(pamh);

                snprintf (agtConnFormTpCode, sizeof (agtConnFormTpCode), "%s", (info->type == 1)? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);
		snprintf (userIp, sizeof (userIp), "%s", info->remote_host);
        	snprintf (connAcctId, sizeof (connAcctId), "%s", info->current_user);

		nd_log (NDLOG_INF, "====================================================================");
		nd_log (NDLOG_INF, "[get ssh session information]"); 
		nd_log (NDLOG_INF, "--------------------------------------------------------------------");
		nd_log (NDLOG_INF, " - nsession type : terminal");
  		nd_log (NDLOG_INF, " - agtConnForm : %s", agtConnFormTpCode);
		nd_log (NDLOG_INF, " - userIp : %s", userIp);
		nd_log (NDLOG_INF, " - connAcctId : %s",  connAcctId );		
		nd_log (NDLOG_INF, "--------------------------------------------------------------------");

		if (validate_json_exceptionConnection(getPamRuleFilePath( sDataHomeDir), userIp) == 1)
		{
			return PAM_SUCCESS;
		}


		if (strcmp (pam_conf.authsvr_linkage, CONF_VALUE_YES) == 0 )
		{
			retval = nd_pam_authenticate_user(uuid_str, info, pamh);
			if (retval != PAM_SUCCESS)
			{
				//
				///
				nd_log (NDLOG_ERR, "pam_sm_authenticate::nd_pam_authenticate_user failed...");
				return retval;
			}

		}
		else
		{
			// BYPASS MODE
			memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));

                        snprintf (sDataEnv_var, sizeof (sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str ? uuid_str : ""  );
                        pam_putenv(pamh, sDataEnv_var);
			
		}

		nd_log (NDLOG_INF, "[ssh] Additional authentication was successful, and the overall login process was completed successfully.");


        } else if (tty && strstr(tty, "pts")) { // SU

		nd_log (NDLOG_INF, "current session type is su.");	

                info = get_su_session_info(pamh);
                snprintf (agtConnFormTpCode, 	sizeof (agtConnFormTpCode), 	"%s", (info->type == 1)? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);
		snprintf (userIp, 		sizeof (userIp), 		"%s", info->remote_host);
                snprintf (connAcctId, 		sizeof (connAcctId), 		"%s", info->target_user);
                snprintf (switchAcctId, 	sizeof (switchAcctId), 		"%s", info->current_user);
		snprintf (securStepNo, 		sizeof (securStepNo), 		"%s", PAM_SECUR_STEP_PAM);
		snprintf (pamCertDtlCode,	sizeof (pamCertDtlCode),	"%s", PAM_SU_LOGIN);
		sprintf  (pamCertDtlAuthCode, "%s", PAM_CERT_DTL_AUTH_PAM_RULE);

		nd_log (NDLOG_INF, "====================================================================");
		nd_log (NDLOG_INF, "[get su session information]");
		nd_log (NDLOG_INF, "--------------------------------------------------------------------");
		nd_log (NDLOG_INF, " - session type : su");
		nd_log (NDLOG_INF, " - agtConnFormTpCode : %s", agtConnFormTpCode);
		nd_log (NDLOG_INF, " - user Ip : %s",userIp);
		nd_log (NDLOG_INF, " - connAcctId : %s",connAcctId);
		nd_log (NDLOG_INF, " - switchAcctId : %s",switchAcctId);
		nd_log (NDLOG_INF, " - securStepNo : %s",securStepNo);
		nd_log (NDLOG_INF, " - pamCertDtlCode : %s",pamCertDtlCode);
		nd_log (NDLOG_INF, " - pamCertDtlAuthCode : %s",pamCertDtlAuthCode);
		nd_log (NDLOG_INF, "--------------------------------------------------------------------");

		if (validate_json_exceptionConnection(getPamRuleFilePath( sDataHomeDir), userIp) == 1)
                {
                        return PAM_SUCCESS;
                }

		isSuSession = true;
		
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

			
		if (check_pam_policy (getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, &pam_pri_no, &agt_auth_no, &pam_action, &pam_logging))
		{
			if (pam_action == PAM_ACT_RULE_DENY)
			{
				snprintf(svrConnFailRsnCode, sizeof(svrConnFailRsnCode), PAM_SVR_FAIL_OS_AUTH_FAIL);
				snprintf(svrConnRstTpCode, sizeof(svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
				snprintf(pamCertDtlAuthCode, sizeof(pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_PAM_RULE);

				nd_log (NDLOG_INF, "PAM Policy verification failed. - Blocked by PAM policy.(%s)", info->current_user);

				retval = PAM_PERM_DENIED;
				goto pam_sm_auth_ex;
			}
			else
			{
				snprintf(svrConnRstTpCode, sizeof(svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);

				bRetPamPolicy = true;

				nd_log (NDLOG_INF, "PAM Policy verification was successful.(%s)", info->current_user);

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
			validate_json_sampolicy_without_date(getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, &ndshell_agtAuthNo, &sam_action, &sam_logging) == 1)
#endif //_SUPP_DATE_
		{

			if (sam_action == PAM_ACT_RULE_DENY )
			{
				snprintf (svrConnFailRsnCode, sizeof (svrConnFailRsnCode), PAM_SVR_FAIL_OS_AUTH_FAIL);
				snprintf (securStepNo, sizeof (securStepNo), "%s", PAM_SECUR_STEP_NDSHELL);
				snprintf (svrConnRstTpCode , sizeof (svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
				snprintf (pamCertDtlAuthCode, sizeof (pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_SAM_RULE);
				
				//
				///
				nd_log (NDLOG_INF, "PAM policy verification completed - Blocked by SAM policy.(%s)", info->current_user);

				retval = PAM_PERM_DENIED;
				goto pam_sm_auth_ex;
			}
			else
			{
				snprintf(svrConnRstTpCode, sizeof(svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);
				bRetSamPolicy = true;
				
				//
				///
				nd_log (NDLOG_INF, "PAM policy verification completed - Allowed by PAM & SAM policy.(%s)", info->current_user);

				retval = PAM_SUCCESS;
			}
		}

		snprintf (agtAuthNo, sizeof (agtAuthNo), "%s", ndshell_agtAuthNo ? ndshell_agtAuthNo : "");

		if (bRetPamPolicy == false && bRetSamPolicy == false)
		{
			//
			///
			nd_log (NDLOG_INF, "Does not comply with the policy - Accepting login without performing additional actions as per the policy.");
			
			return PAM_SUCCESS;
		}


		retval = PAM_SUCCESS;
		goto pam_sm_auth_ex;
        }else
	{
		//
		///
		nd_log (NDLOG_INF, "current session type is console.");
		
		info = get_console_session_info(pamh);
                snprintf (userIp, sizeof (userIp), "%s", info->remote_host);
                snprintf (connAcctId, sizeof (connAcctId), "%s", info->current_user);
		snprintf (agtNo , sizeof (agtNo), "%s", agent_id);
                snprintf (agtConnFormTpCode,    sizeof (agtConnFormTpCode), "%s", PAM_CONN_CONSOLE);
		snprintf (securStepNo, sizeof (securStepNo), "%s", PAM_SECUR_STEP_PAM);

		if (validate_json_exceptionConnection(getPamRuleFilePath( sDataHomeDir), userIp) == 1)
                {
                        return PAM_SUCCESS;
                }
			

		const char *service;
		 retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
		if (retval != PAM_SUCCESS) {

			//
			///
			nd_log (NDLOG_ERR, "failed to get service information...[pam_get_item:service]");
			return retval;
		}

		/*
			// Proceed with processing if the entered command is either 'su' or 'su -l'. Detect both cases based on the usage of the 'su' command.
		*/
		if (service != NULL && (strcmp (service, STR_SU) == 0 || strcmp (service, STR_SUL) == 0))
		{
			if (check_pam_policy (getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, &pam_pri_no, &agt_auth_no, &pam_action, &pam_logging))
                	{
				if (pam_action == PAM_ACT_RULE_DENY)
				{
					snprintf(svrConnFailRsnCode, sizeof(svrConnFailRsnCode), PAM_SVR_FAIL_OS_AUTH_FAIL);
					snprintf(svrConnRstTpCode, sizeof(svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
					snprintf(pamCertDtlAuthCode, sizeof(pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_PAM_RULE);
			
					//
					///
					nd_log (NDLOG_INF, "PAM Policy verification failed. - Blocked by PAM policy.(%s)", info->current_user);
					retval = PAM_PERM_DENIED;
					goto pam_sm_auth_ex;
				}
				else
				{
					snprintf(svrConnRstTpCode, sizeof(svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);

					//
					///
					nd_log (NDLOG_INF, "PAM Policy verification was successful.(%s)", info->current_user);

					bRetPamPolicy = true;

					retval = PAM_SUCCESS;
				}

			}
      
			snprintf (pamAgtAuthNo, sizeof (pamAgtAuthNo), "%s", agt_auth_no ? agt_auth_no : "");
      			bool isNdShell = is_pam_user_ndshell(pamh);
			if (isNdShell == true )
			{
				if (validate_json_sampolicy_without_date(getPamRuleFilePath( sDataHomeDir), info->remote_host, info->target_user, &ndshell_agtAuthNo, 
												&sam_action, &sam_logging) == 1)
				{
					snprintf (agtNo ,               sizeof (agtNo),                 "%s", agent_id);
					snprintf (agtConnFormTpCode,    sizeof (agtConnFormTpCode),     "%s", PAM_CONN_BYPASS);
					snprintf (agtAuthNo ,           sizeof (agtAuthNo),             "%s", ndshell_agtAuthNo ? ndshell_agtAuthNo : "");
					snprintf (userIp ,              sizeof (userIp),                "%s", info->remote_host ? info->remote_host : "");
					snprintf (securStepNo ,         sizeof (securStepNo),           "%s", PAM_SECUR_STEP_NDSHELL );
					snprintf (svrConnSessKey ,      sizeof (svrConnSessKey),        "%s", uuid_str ? uuid_str : "");
					snprintf (connAcctId ,          sizeof (connAcctId) ,           "%s", info->target_user ? info->target_user : "");
					snprintf (switchAcctId ,        sizeof (switchAcctId),          "%s", info->current_user ? info->current_user : "" );
					snprintf (pamAgtAuthNo ,        sizeof (pamAgtAuthNo),          "%s", agt_auth_no ? agt_auth_no : "" );
					snprintf (pamCertDtlCode ,      sizeof (pamCertDtlCode),        "%s", PAM_SU_LOGIN );
					snprintf (pamCertDtlAuthCode ,  sizeof (pamCertDtlAuthCode),    "%s", PAM_CERT_DTL_AUTH_SAM_RULE );
				
					if (sam_action ==  PAM_USER_RULE_ACT_DENY )
					{
						snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_AUTH_FAIL);
						snprintf (svrConnFailRsnCode ,	sizeof (svrConnFailRsnCode),	"%s", PAM_SVR_FAIL_OS_AUTH_FAIL); 

						//
						///
						nd_log (NDLOG_INF, "PAM Policy verification failed. - Blocked by SAM policy.(%s)", info->current_user);
					
						retval = PAM_PERM_DENIED;
						goto pam_sm_auth_ex;

					}
					else
					{
						snprintf (svrConnRstTpCode ,    sizeof (svrConnRstTpCode),      "%s", PAM_AUTH_SUCCESS);
						
						//
						///
						nd_log (NDLOG_INF, "PAM policy verification completed - Allowed by PAM & SAM policy.(%s)", info->current_user);

						bRetSamPolicy = true;

						retval = PAM_SUCCESS;
					}

				}
				
			}
		}
		else
		{
			retval = nd_pam_authenticate_user(uuid_str, info, pamh);
			if (retval != PAM_SUCCESS)
			{
				//
				///
				nd_log (NDLOG_ERR, "pam_sm_authenticate::nd_pam_authenticate_user failed...");
				return retval;
			}

			nd_log (NDLOG_INF, "[console] Additional authentication was successful, and the overall login process was completed successfully.");

		}

	} 
	

 pam_sm_auth_ex:

	if (pam_logging == LOGGING_ON)  {

                logitem =  create_archive_log (svrConnStartTime, svrConnEndTime, svrConnRstTpCode, svrConnFailRsnCode, agtNo, agtConnFormTpCode,
                                                agtAuthNo, portNo, userIp, securStepNo, svrConnSessKey, connAcctId, switchAcctId, pamAgtAuthNo, userNo, pamCertDtlCode,pamCertDtlAuthCode,
                                                certTpCode, certAppTpCode,certSucesFailYn,certStepSeqNo);

                nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
                free_archive_log(logitem);
        }


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

	bool bIsConsole = false;
	struct  st_pam_conf pam_conf;
	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
        if (sDataHomeDir == NULL)
                sDataHomeDir = strdup(PRODUCT_NM);

	if (sDataHomeDir != NULL )
		g_sDataRootDir = strdup (sDataHomeDir);

        if (g_sConfFilePath == NULL )
                g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	/*
                // get pam config
        */
        getpamconf (&pam_conf);
        if (pam_conf.pam_operate_mode != MODE_ON)
                return PAM_SUCCESS;

	system("clear");
	const char *tty = get_pam_item_str(pamh, PAM_TTY);
        if (tty && strstr(tty, "ssh") || tty && strstr(tty, "pts")) {

		bIsConsole = false;
	}else
		bIsConsole = true;

	parse_ssh_connection(pamh, bIsConsole);

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

	char agt_auth_Number[4] = {0,};
	char pamCertDtlCode[4] = {0,};
	char agtConnFormTpCode[4] = {0,};
	bool isConsole		= NULL;
	SessionInfo *info = NULL;
	struct _archive_log         *logitem;
	struct  st_pam_conf         pam_conf;

	const char *service = get_pam_item_str(pamh, PAM_SERVICE);
	const char *tty = get_pam_item_str(pamh, PAM_TTY);
	const char *rhost = get_pam_item_str(pamh, PAM_RHOST);
	const char *user = get_pam_item_str(pamh, PAM_USER);

        struct _msg_header_ header = {

                .iMsgTotalSize  = 0,
		.iMsgType 	= 0,
		.iMsgCode 	= 0
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

	if (sDataHomeDir != NULL )
		g_sDataRootDir = strdup (sDataHomeDir);

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

	sprintf ((char *)header.sAgentId, agent_id ? agent_id : "");
        sprintf ((char *)header.iMsgVer, "%s", ND_PAM_VERSION);

	if (sessionkey == NULL )
	{
		sessionkey = getenv (ENV_HIWARE_SESSIONKEY);
	}

	snprintf (pamCertDtlCode ,sizeof (pamCertDtlCode),"%s", PAM_LOGOUT );
	snprintf (agtConnFormTpCode , sizeof (agtConnFormTpCode), "%s", PAM_CONN_BYPASS);

        if (tty && strstr(tty, "ssh")) {
                info = get_ssh_session_info(pamh);
        } else if (tty && strstr(tty, "pts")) {
                info = get_su_session_info(pamh);
		snprintf (pamCertDtlCode ,sizeof (pamCertDtlCode),"%s", PAM_SU_LOGOUT );
        } else {
                info = get_console_session_info(pamh);
		snprintf (agtConnFormTpCode , sizeof (agtConnFormTpCode), "%s", PAM_CONN_CONSOLE);
		const char *service;
                int retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);

		if (service != NULL && (strcmp (service, STR_SU) == 0 || strcmp (service, STR_SUL) == 0))
		{
			snprintf (pamCertDtlCode ,sizeof (pamCertDtlCode),"%s", PAM_SU_LOGOUT );
		}
        }

	check_pam_policy (getPamRuleFilePath( sDataHomeDir), info->remote_host, info->current_user, &pri_no, &agt_auth_no, &action, &logging);

	if (logging == LOGGING_ON) // 1
	{
		
		logitem =  create_archive_log ("", "", PAM_AUTH_SUCCESS, "", agent_id, agtConnFormTpCode, /*agtAuthNo*/"", "", info->remote_host,PAM_SECUR_STEP_PAM,
                                                               sessionkey, info->current_user, "", (agt_auth_no)?agt_auth_no:"", /*agent_id*/"", pamCertDtlCode, "" ,"","","","");
		nd_pam_archive_log(header, *logitem, (char*)sDataHomeDir);
                free_archive_log(logitem);
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
