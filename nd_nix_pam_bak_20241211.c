
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
//#include "nd_pam.pb-c.h"
#include <pthread.h>
#include <sys/time.h> 
#include <sys/file.h>
#include <uuid/uuid.h>
//#include "./libsrc/nd_ssl_func.h"
#include "./libsrc/nd_utils.h"
#include "./libsrc/nd_nix_logs.h"
#include "./libsrc/nd_restapi_func.h"
//#include "./libsrc/nd_auth_func.h"
#include <json-c/json.h>
#include <curl/curl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <dlfcn.h> 
#include <curl/curl.h>

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
int pam_check_su_check_user(char * current_account, char * switch_user, struct st_auth_result_data * ret_data , pam_handle_t *pamh);

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

char g_sDataAgentId[2];


static const char *current_user;

pthread_mutex_t session_id_mutex;


/*
#define __FILENAME__ (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/')+1) : __FILE__)
#define nd_log(level, fmt, ...) nd_pam_log(level, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__)
*/
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

/*
 	//pam log
	//Function to log messages in the PAM module.
*/
void nd_pam_log_bak(int level, char* filename, int line, const char *fmt, ...)	{

	char timestamp[50];
	size_t len;
	va_list args;
	const char *log_file = "/netand/log/nd_pam_log.log";
	char sLogMsg[1024] = {0,}, sBakStr[1024] = {0,};

	get_timestamp(timestamp, sizeof (timestamp));
	va_start(args, fmt);
	vsnprintf (sBakStr, sizeof (sBakStr), fmt, args);
	va_end(args);

	len = strlen(sBakStr);

	snprintf (sLogMsg, sizeof (sLogMsg), "%s(%s) <%s:%d>    %s\n",timestamp, nd_log_level[level].stLevel, filename, line, sBakStr);

	if (sLogMsg[strlen(sLogMsg) -1] == '\n')
		sLogMsg[strlen(sLogMsg) -1] = '\0';

	FILE *file = fopen(log_file, "a");
	if (file) {

		fprintf(file, "%s\n", sLogMsg);
		fclose(file);
	} 
}

//void nd_pam_sulog(int level, char* filename, int line, const char *fmt, ...) ;


#ifdef _LOG_TYPE_V2
void nd_pam_log_v2(struct pam_log_item * plog)
{
	const char *log_file = "/netand/log/nd_pam_log.log";

	if (plog == NULL )
		return;

	char sLogMsg[1024] = {0,};

	snprintf (sLogMsg, sizeof (sLogMsg), ND_PAMLOG_FORMAT_V2,plog->action_type, plog->session_status, plog->account, plog->ipaddr, plog->sessionKey, plog->message);

	if (sLogMsg[strlen(sLogMsg) -1] == '\n')
                sLogMsg[strlen(sLogMsg) -1] = '\0';

	FILE *file = fopen(log_file, "a");
        if (file) {

                fprintf(file, "%s\n", sLogMsg);
                fclose(file);
        }
}
#endif

/*
        //pam log
        //Function to log messages in the PAM module.
*/
void nd_pam_sulog_bak(int level, char* filename, int line, const char *fmt, ...)      {

        char timestamp[50];
        size_t len;
        va_list args;
        const char *log_file = PAM_BACKUP_SULOG_FILE;
        char sLogMsg[1024] = {0,}, sBakStr[1024] = {0,}, sDummStr[1024] = {0,}, sDummySizeString[8] = {0,};

        get_timestamp(timestamp, sizeof (timestamp));
        va_start(args, fmt);
        vsnprintf (sBakStr, sizeof (sBakStr), fmt, args);
        va_end(args);

        len = strlen(sBakStr);

        snprintf (sLogMsg, sizeof (sLogMsg), "%s(%s) <%s:%d>    %s\n",timestamp, nd_log_level[level].stLevel, filename, line, sBakStr);

        if (sLogMsg[strlen(sLogMsg) -1] == '\n')
                sLogMsg[strlen(sLogMsg) -1] = '\0';

        FILE *file = fopen(log_file, "a");
        if (file) {

                fprintf(file, "%s\n", sLogMsg);
                fclose(file);
        }
}

/*
	// type : 0 = open(connect), 1 = close (disconnect)
	// Function to log user login/logout session activities.
*/
void nd_pam_session_log_bak(int type, const char *fmt, ...)      {

        char timestamp[50];
        size_t len;
        va_list args;
	int dummyStrLen = 0;
        const char *log_file = "/netand/log/nd_pam_session.log";
        char sLogMsg[1024] = {0,}, sBakStr[1024] = {0,}, sDummStr[1024] = {0,}, sDummySizeString[8] = {0,} ;

        //get_timestamp(timestamp, sizeof (timestamp));
        va_start(args, fmt);
        vsnprintf (sBakStr, sizeof (sBakStr), fmt, args);
        va_end(args);

        len = strlen(sBakStr);

        if (len == 0 || sBakStr[len-1] != '\n') {
                snprintf (sLogMsg, sizeof (sLogMsg), "%s|%s\n", nd_slog_type[type].stType,  sBakStr);
        }else
        {
		snprintf (sLogMsg, sizeof (sLogMsg), "%s|%s", nd_slog_type[type].stType,  sBakStr);
        }

        FILE *file = fopen(log_file, "a");
        if (file) {

                fprintf(file, "%s", sLogMsg);
                fclose(file);
        }
}



/*
	//Function to verify compliance with policies using the information of the access subject stored in the local policy file.
*/
bool find_match_rule (struct pam_rule_info *rule)
{

	FILE *file = fopen (PAM_RULE_FILE, "r");
	if (file == NULL )	{
		return false;
	}

	char line[MAX_LINE_LENGTH];
	while (fgets (line, sizeof (line), file) != NULL )	{

		line [strcspn(line, "\n")] = 0;

		char * token = strtok(line, "|");
		struct pam_rule_info temp_rule;
		memset (&temp_rule, 0, sizeof (temp_rule));

		int index = 0;
		while (token != NULL && index < 5)	{
			switch (index )	{

				case 0: //USER NAME
					strncpy (temp_rule.username, token, sizeof (temp_rule.username) -1);
					break;

				case 1: //ip address
					strncpy (temp_rule.ipaddr, token, sizeof (temp_rule.ipaddr) -1 );
					break;

				default:
					break;
				
			}

			index ++;
			token = strtok(NULL, "|");
		}

		if (
			strcmp (temp_rule.username, rule->username) == 0 &&
			strcmp (temp_rule.ipaddr, rule->ipaddr) == 0	
			
			/*&& 
			temp_rule.isMFA == rule->isMFA &&
			strcmp (temp_rule.hiwareAccount, rule->hiwareAccount) == 0 &&
			strcmp (temp_rule.hiwareActualName, rule->hiwareActualName) == 0 
			*/
		) 
		{
			fclose (file);
			return true;
		}
	}

	fclose (file);

	return false;
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
        //Function to verify compliance with policies using the information of the access subject stored in the local policy file.
*/
bool find_match_rule_for_connnectinfo (const char *username, const char * remoteipaddr/*, bool * isMFA*/)
{

        FILE *file = fopen (PAM_RULE_FILE, "r");
        if (file == NULL )      {
                return false;
        }

        char line[MAX_LINE_LENGTH];
        while (fgets (line, sizeof (line), file) != NULL )      {

                line [strcspn(line, "\n")] = 0;

                char * token = strtok(line, "|");
                struct pam_rule_info temp_rule;
                memset (&temp_rule, 0, sizeof (temp_rule));

                int index = 0;
                while (token != NULL && index < 5)      {
                        switch (index ) {

				case 0: //USER NAME
                                        strncpy (temp_rule.username, token, sizeof (temp_rule.username) -1);
                                        break;

                                case 1: //ip address
                                        strncpy (temp_rule.ipaddr, token, sizeof (temp_rule.ipaddr) -1 );
                                        break;

                                default:
                                        break;

                        }

                        index ++;
                        token = strtok(NULL, "|");
                }

                if (
                        strcmp (temp_rule.username, username) == 0 &&
                        strcmp (temp_rule.ipaddr, remoteipaddr) == 0 
                )
                {
                        fclose (file);
                        return true;
                }
        }

        fclose (file);

        return false;
}

bool check_su_permission(const char *username, const char *remoteipaddr, const char *su_user, const char *policy_file) {

	FILE *file = fopen(policy_file, "r");
	if (file == NULL) {
		perror("Failed to open policy file");
		return false; // File could not be opened
	}

	char policy_line[512]; // Buffer to hold each policy line
	bool permission_granted = false;

	while (fgets(policy_line, sizeof(policy_line), file) != NULL) {
		// Remove newline character from the end of the line
		policy_line[strcspn(policy_line, "\n")] = 0;

		// Extract <ip_address> and <username1>,<username2>,<username3>
		char ip_address[16]; // IPv4 address max length
		char users[256]; // User list max length
		sscanf(policy_line, "%15[^|]|%255[^|]|", ip_address, users);

		// Check if remoteipaddr matches ip_address
		if (strcmp(remoteipaddr, ip_address) != 0) {
			continue; // Skip to the next policy line
		}

		// Check if username and su_user are in the users list
		bool username_found = false;
		bool su_user_found = false;

		// Split the users list by ',' and check for matches
		char *token = strtok(users, ",");
		while (token != NULL) {
	    		if (strcmp(token, username) == 0) {
				username_found = true; // username is in the list
	    		}
	    		if (strcmp(token, su_user) == 0) {
				su_user_found = true; // su_user is in the list
	    		}
	    		token = strtok(NULL, ",");
		}

		// If both username and su_user are found, permission is granted
		if (username_found && su_user_found) {
		    permission_granted = true;
		    break; // No need to check further policies
		}
	}

	fclose(file); // Close the file
	return permission_granted; // Return the result
}


/*
	//get user information
*/
void get_user_info(struct pam_user_info *user_info,  pam_handle_t *pamh) {

	char *crypted;
	const char *input_passwd;
	const char *encrypted_passwd;
	const char *current_user;
	const char *switch_user;
	struct st_auth_result_data  ret_data;
	struct st_hiauth_su_login_result su_login_ret;
	struct st_hiauth_su_access_perm_result su_access_perm;
	bool bJumpPwd = false;
	bool bIsSuFailed = false;
    int retval = 0;

	nd_log (NDLOG_INF, "====================================================================");
	nd_log (NDLOG_INF, "[get pam session user information]");
	nd_log (NDLOG_INF, "--------------------------------------------------------------------");

	char * authsvr_emergency_act = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_PAM_CONF,PAM_AUTHSVR_EMERGENCY_ACTION);  // PAM_AUTHSVR_EMERGENCY_ACTION

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
		const char * uidUser, *envuser;
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

	//nd_log (LOG_LEVEL_INFO, "\t- user password         :%s", input_passwd);

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
		if (strcmp(crypted, user_info->encrypted_password) == 0) {
			user_info->login_status = 0;
		} else {
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
	if (pw != NULL) {
		user_info->uid = pw->pw_uid;
		user_info->gid = pw->pw_gid;
		strncpy(user_info->home_directory, pw->pw_dir, sizeof(user_info->home_directory) - 1);
		user_info->home_directory[sizeof(user_info->home_directory) - 1] = '\0';
		strncpy(user_info->shell, pw->pw_shell, sizeof(user_info->shell) - 1);
		user_info->shell[sizeof(user_info->shell) - 1] = '\0';
	}

	nd_log (NDLOG_INF, "\t- user uid          :%d", user_info->uid);
	nd_log (NDLOG_INF, "\t- user gid          :%d", user_info->gid);

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

	if (pamh == NULL || data_name == NULL || data_value == NULL) {
		return PAM_BUF_ERR; 
	}

	char *data_copy = strdup(data_value);	// strdup performs a similar role to malloc by allocating memory and copying the string
	if (data_copy == NULL) {
		return PAM_BUF_ERR;
	}

	int retval = pam_set_data(pamh, data_name, data_copy, cleanup_func);
	if (retval != PAM_SUCCESS) {
		free(data_copy); 
	}

	return retval;
}

int get_pam_data(pam_handle_t *pamh, const char *data_name, const void **data_out) 	{

	if (pamh == NULL || data_name == NULL || data_out == NULL) {
		return PAM_BUF_ERR; 
	}

	int retval = pam_get_data(pamh, data_name, data_out);
	if (retval != PAM_SUCCESS) {
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
	bool bFinded = false;
	bool found = false;
	int retval = 0;
	pam_client_info clientInfo;
	const char *ssh_connection = getenv("SSH_CONNECTION");

	strcpy(clientInfo.ip, NONE_STRING);
    	strcpy(clientInfo.port, NONE_STRING);
    	strcpy(clientInfo.tty, NONE_STRING);

	if (ssh_connection) {
		// SSH_CONNECTION format: "client_ip client_port server_ip server_port"
		char *token = strtok((char *)ssh_connection, " ");
		if (token != NULL) {
			strncpy(clientInfo.ip, token, INET_ADDRSTRLEN); 
			clientInfo.ip[INET_ADDRSTRLEN - 1] = '\0'; // null-terminate

			token = strtok(NULL, " ");
			if (token != NULL) {
				strncpy(clientInfo.port, token, sizeof(clientInfo.port)); 
				clientInfo.port[sizeof(clientInfo.port) - 1] = '\0'; 
			}
		}
		found = true;
	} else {

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
			    		char *user = strtok(buffer, " ");
			    		char *tty1 = strtok(NULL, " ");
			    		char *time = strtok(NULL, " ");
			    		time = strtok(NULL, " ");
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

	if (!found) {
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

	if (input_data == NULL) {
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
	int retval = 0;
	if (tty == NULL  )
	{
		syslog (LOG_ERR, "check_session_type -- TEST001");
		retval = -2;
	}
	
	if (service == NULL)
	{
		syslog (LOG_ERR, "check_session_type -- TEST002");
		retval = -3;
	}
	
	if (strncmp(tty, "tty", 4) == 0) 		{
		syslog (LOG_ERR, "check_session_type -- TEST003");
        	return AUTH_PURPOS_CONSOLE;  

    	} else if (strncmp(tty, "/pts/", 5) == 0) 	{

		syslog (LOG_ERR, "check_session_type -- TEST004");
        	return AUTH_PURPOS_TERMINAL; 
  	}

	if (strcmp (service, STR_SU) == 0 || strcmp (service, STR_SUL) == 0)	{
		syslog (LOG_ERR, "check_session_type -- TEST005");
		return AUTH_PURPOS_SU;
	}

	syslog (LOG_ERR, "check_session_type -- TEST006 (SERICE :%s)", service);
    	return -1;
}

/*
	// pam_check_su_check_user
*/
int pam_check_su_check_user(char * current_account, char * switch_user, struct st_auth_result_data * ret_data, pam_handle_t *pamh)
{
	int retval = 0, sock = 0;
	char sSendBuffer[MAX_SEND_DATA];
	char sRecvBuffer[MAX_RECV_DATA];

	char * server_pam_mode  = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_PAM_CONF,     PAM_CONF_KEY_PAM_MODE);         // PAM_MODE
    	char * server_su_mode   = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_PAM_CONF,     PAM_CONF_KEY_SU_CONTROL);       // PAM_SU_CONTROL
	char * authsvr_linkage  = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_PAM_CONF,     PAM_AUTHSVR_LINKAGE);           // PAM_AUTHSVR_LINKAGE
	char * authsvr_emergency_act = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_PAM_CONF,PAM_AUTHSVR_EMERGENCY_ACTION);  // PAM_AUTHSVR_EMERGENCY_ACTION

	ret_data->currentprocess        = PAM_PROCESS_SUAUTH;
	ret_data->nextprocess           = PAM_PROCESS_NONE;
	ret_data->AuthExt               = PAM_EXTAUTH_NONE;

	if (	strcmp (server_pam_mode, SET_MODE_OFF) 	== 0 	||
			strcmp (server_su_mode,  SET_MODE_OFF) 	== 0 	||
			strcmp (authsvr_linkage, CONF_VALUE_NO) == 0)
	{
		ret_data->ret           = PAM_SUCCESS;
		close (sock);
        return PAM_SUCCESS;
	}

	retval = connect_to_server(&sock, SECTION_NM_HIAUTH_CONF);
	if (retval != 0 )
	{
		char * authsvr_emergency_act = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_PAM_CONF,PAM_AUTHSVR_EMERGENCY_ACTION);  // PAM_AUTHSVR_EMERGENCY_ACTION
		if (authsvr_emergency_act &&  strcmp (authsvr_emergency_act, SET_MODE_BYPASS) == 0 )
		{
			ret_data->ret           = PAM_SUCCESS;
			close (sock);
			return PAM_SUCCESS;
		}
		else
		{
			ret_data->ret                   = PAM_AUTH_ERR;

			retval = PAM_AUTH_ERR;
			goto exitfunc;
		}
    }

	snprintf (sSendBuffer, sizeof (sSendBuffer), STR_FORMAT_SU_CHECK_USER, current_account, switch_user);

	retval = send_data (sock, sSendBuffer);
	if (retval != 0 )
	{
		ret_data->ret                   = PAM_AUTH_ERR;

		retval = PAM_AUTH_ERR;
		goto exitfunc;
	}

	retval = receive_data (sock, sRecvBuffer, sizeof (sRecvBuffer));
	if (retval != 0 )
	{
		ret_data->ret                   = PAM_AUTH_ERR;

		retval = PAM_AUTH_ERR;
		goto exitfunc;
	}

	if (strcmp (sRecvBuffer, "SWITCH_ALLOW") == 0)
	{
		ret_data->ret           = PAM_SUCCESS;
		close (sock);
        return PAM_SUCCESS;
	}	
	else
	{
		ret_data->ret           = PAM_AUTH_ERR;

		retval = PAM_AUTH_ERR;
		goto exitfunc;
	}

exitfunc:

	close (sock);
	return retval;
}

/*
	// check user
*/
int pam_check_user (char * sAccount , struct st_auth_result_data * ret_data)
{
	int retval = 0, sock = 0;
	char sSendBuffer[MAX_SEND_DATA];
	char sRecvBuffer[MAX_RECV_DATA];

	ret_data->currentprocess        = PAM_PROCESS_OSAUTH;
    	ret_data->nextprocess   	= PAM_PROCESS_NONE;
    	ret_data->AuthExt       	= PAM_EXTAUTH_NONE;


	retval = connect_to_server(&sock, "HIAUTH_CONF");
	if (retval != 0 )
	{
		ret_data->ret 				= PAM_AUTH_ERR;
		
		retval = PAM_AUTH_ERR;
		goto exitfunc;
	}

	snprintf (sSendBuffer, sizeof (sSendBuffer),  STR_FORMAT_CHECK_USER, sAccount);

	retval = send_data (sock, sSendBuffer);
	if (retval != 0 )
	{
		ret_data->ret           	= PAM_AUTH_ERR;

		retval = PAM_AUTH_ERR;
		goto exitfunc;
	}

	retval = receive_data (sock, sRecvBuffer, sizeof (sRecvBuffer));
	if (retval != 0 )
	{
		ret_data->ret           	= PAM_AUTH_ERR;

		retval = PAM_AUTH_ERR;
		goto exitfunc;
	}

	if (strcmp (sRecvBuffer, "REQ_HIAUTH") == 0 || strcmp (sRecvBuffer, "AUTH_OK") == 0)
	{
		ret_data->ret           	= PAM_SUCCESS;

		if (strcmp (sRecvBuffer, "REQ_HIAUTH") == 0)
		{
			ret_data->nextprocess   = PAM_PROCESS_HIWARE;
            		ret_data->AuthExt       = PAM_EXTAUTH_NONE;
		}

		close (sock);
		return PAM_SUCCESS;
	}

	else
	{
		ret_data->ret           = PAM_AUTH_ERR;

        	retval = PAM_AUTH_ERR;
        	goto exitfunc;
	}

exitfunc:

	close (sock);
	return retval;	
}

/*
	//
*/
int pam_hiware_auth_process(char * uuid_str, const char * hiauthID, const char * hiauthPW, struct st_auth_result_data * ret_data,  pam_handle_t * pamh)
{
	int retval = 0, sock = 0;
	char sSendBuffer[MAX_SEND_DATA];
        char sRecvBuffer[MAX_RECV_DATA];

	ret_data->currentprocess        = PAM_PROCESS_OSAUTH;
	ret_data->nextprocess   		= PAM_PROCESS_NONE;
    	ret_data->AuthExt       		= PAM_EXTAUTH_NONE;

	retval = connect_to_server(&sock, "HIAUTH_CONF");
        if (retval != 0 )
	{
		ret_data->ret                   = PAM_AUTH_ERR;
		return PAM_AUTH_ERR;
	}


//////HIWARE AUTH TEST START
	send_hiware_login_request(hiauthID, hiauthPW);

	nd_log (NDLOG_INF, "====================================================================");
	nd_log (NDLOG_INF, "[get hiware login result data]");
	nd_log (NDLOG_INF, "--------------------------------------------------------------------");

	nd_log (NDLOG_INF, "\t- secretkey :    %s", getSecretKey());
	nd_log (NDLOG_INF, "\t- IssueKey :    %s", getIssueKey());
	nd_log (NDLOG_INF, "\t- RandomKey :    %s", getRandomKey());
	nd_log (NDLOG_INF, "\t- UserNumber :    %s", getUserNumber());
	nd_log (NDLOG_INF, "\t- AuthKey :    %s", getAuthKey());

	nd_log (NDLOG_INF, "--------------------------------------------------------------------");

	pam_syslog (pamh, LOG_ERR, "getSecretKey   : %s", getSecretKey());
	pam_syslog (pamh, LOG_ERR, "getIssueKey    : %s", getIssueKey());
	pam_syslog (pamh, LOG_ERR, "getRandomKey   : %s", getRandomKey());
	pam_syslog (pamh, LOG_ERR, "getUserNumber  : %s", getUserNumber());
	pam_syslog (pamh, LOG_ERR, "getAuthKey     : %s", getAuthKey());
//////HIWARE AUTH TEST END
	snprintf (sSendBuffer, sizeof (sSendBuffer), STR_FORMAT_HIWARE_AUTH, hiauthID, hiauthPW, uuid_str);	
	
	retval = send_data (sock, sSendBuffer);
	if (retval != 0)
	{
		ret_data->ret                   = PAM_AUTH_ERR;
		retval	= PAM_AUTH_ERR;
		goto exitfunc;
	}

	retval = receive_data ( sock, sRecvBuffer, sizeof (sRecvBuffer));
	if (retval != 0 )
	{
		ret_data->ret                   = PAM_AUTH_ERR;
		retval = PAM_AUTH_ERR;
                goto exitfunc;
	}

	if (strcmp (sRecvBuffer, "AUTH_OTP") == 0 || strcmp (sRecvBuffer, "AUTH_FIDO") == 0 || strcmp (sRecvBuffer, "AUTH_OK") == 0)
	{
		ret_data->ret           	= PAM_SUCCESS;

		if (strcmp (sRecvBuffer, "AUTH_OTP") == 0)
		{
			ret_data->nextprocess 	= PAM_PROCESS_TWOFACT;
			ret_data->AuthExt	= PAM_EXTAUTH_OTP;
		}

		else if (strcmp (sRecvBuffer, "AUTH_FIDO") == 0 )
		{
			ret_data->nextprocess 	= PAM_PROCESS_TWOFACT;
			ret_data->AuthExt       = PAM_EXTAUTH_FIDO;
		}

		else
		{
			// not set
		}
	}
	
	else
	{
		ret_data->ret           = PAM_AUTH_ERR;

		retval = PAM_AUTH_ERR;
		goto exitfunc;

	}
	
exitfunc:

	close (sock);

	return retval;	
}

/*
	//
*/
int pam_twofact_auth_process(char * uuid_str, int nTwoFactType, char * sDataTwofact, struct st_auth_result_data * ret_data,  pam_handle_t * pamh)
{
	int retval = 0, sock = 0;
        char sSendBuffer[MAX_SEND_DATA];
        char sRecvBuffer[MAX_RECV_DATA];

        ret_data->currentprocess        = PAM_PROCESS_HIWARE;
        ret_data->nextprocess           = PAM_PROCESS_NONE;
        ret_data->AuthExt               = PAM_EXTAUTH_NONE;

        retval = connect_to_server(&sock, "HIAUTH_CONF");
        if (retval != 0 )
        {
                ret_data->ret                   = PAM_AUTH_ERR;
                return PAM_AUTH_ERR;
        }

	if (nTwoFactType == PAM_EXTAUTH_OTP)
	{
		ret_data->currentprocess        = PAM_PROCESS_TWOFACT;
		ret_data->AuthExt		= PAM_EXTAUTH_OTP;
		snprintf (sSendBuffer, sizeof (sSendBuffer), STR_FORMAT_OTP_AUTH, sDataTwofact);
	}

	else if (nTwoFactType == PAM_EXTAUTH_FIDO)
	{
		ret_data->currentprocess        = PAM_PROCESS_TWOFACT;
		ret_data->AuthExt               = PAM_EXTAUTH_FIDO;

		snprintf (sSendBuffer, sizeof (sSendBuffer), STR_FORMAT_FIDO_AUTH, sDataTwofact);
	}
	
	else
	{
		ret_data->ret = PAM_SUCCESS;
		close (sock);
		return PAM_SUCCESS;
	}

	retval = send_data (sock, sSendBuffer );
	if (retval != 0 )
	{
		ret_data->ret = retval = PAM_AUTH_ERR;
	
                goto exitfunc;

	}

	retval = receive_data ( sock, sRecvBuffer, sizeof (sRecvBuffer));
        if (retval != 0 )
        {
                ret_data->ret =  retval = PAM_AUTH_ERR;
		retval = PAM_AUTH_ERR;
                goto exitfunc;
        }

	if (strcmp (sRecvBuffer, "AUTH_FAIL") == 0 )
	{
		ret_data->ret = retval = PAM_AUTH_ERR;
                goto exitfunc;
	}
	
	else 
	{
		ret_data->ret = retval = PAM_SUCCESS;
		retval = PAM_SUCCESS;
	}


exitfunc:

	close (sock);

	return retval;
}

int nd_pam_authenticate_user (char * uuid_str, struct pam_user_info user_info, pam_handle_t * pamh)
{
	int authsvr_port = 0;
	int retval = 0;

	char  	*hiwareTwoFactData = NULL;
	char 	sTwoFactString[128];
	char    sActionTypeString[128];
	char    sDataCollocLog[MAX_STRING_LENGTH];
	char 	sTemp[128] = {0,};
	char 	sDataAgtId[8] = {0,};
	char    sDataEnv_var[MAX_ENV_STR_LEN];
	sprintf (sTwoFactString, "OTP(One-Time Password): ");

	struct st_hiauth_input_data    			*hiauth_input_data;
	struct st_hiauth_os_login_result 		hi_osauth_ret;
	struct st_hiauth_hiware_login_result 	hi_hiwareauth_ret;
	struct st_hiauth_twofact_login_result 	hi_twofactauth_ret;
	struct _msg_header_             header = {

                .iMsgVer        = 0,
                .iMsgTotalSize  = 0
        };


	/*
		// Retrieve the server connection information from the configuration file.
	*/
	char * auth_server_ip   = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERIP);
    	char * auth_server_port = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERPORT); 
	char * authsvr_emergency_act = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_PAM_CONF,PAM_AUTHSVR_EMERGENCY_ACTION);

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

	/*
		// dose not use
		// Send OS account information to the API server to perform authentication.
	*/
	/*
	retval = requestOSAuthToApiServer(user_info.username, user_info.realpwd, &hi_osauth_ret);
	if (retval != HI_AUTH_RET_SUCCEED)
		return PAM_AUTH_ERR;

	nd_log (NDLOG_INF, "Authentication task for system account with the authentication server succeeded.");
	*/

	PamPolicy pamPolicy = parsePamPolicy(PAM_RULE_FILE);
	Rule *matchedRule = isPamPolicyMatched(&pamPolicy, user_info.ip_address, user_info.username);

	if (matchedRule)
	{
		if (matchedRule->action == PAM_USER_RULE_ACT_DENY)
		{
			header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                	header.iMsgCode = PACK_MSG_CODE_REJECT_PASSWD;

			sprintf (sActionTypeString, "%s:auth", user_info.service);
			sprintf (sTemp, "Permission denied for %s from %s",user_info.username,user_info.ip_address);

                	nd_pam_log(header, (char*)matchedRule->agtAuthNo, sDataAgtId,  sActionTypeString, "Authentication failed", user_info.username, user_info.ip_address, uuid_str, sDataCollocLog,
                                        sTemp);

			return PAM_PERM_DENIED; 
		}
		//HIWARE_AGTAUTHNO_KEY_FORMAT

		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_AGTAUTHNO_KEY_FORMAT, matchedRule->agtAuthNo);
        	pam_putenv(pamh, sDataEnv_var);

		sprintf (user_info.agtAuthNo, "%s", matchedRule->agtAuthNo);
	}
	else
	{
		syslog (LOG_ERR, "No matching rule found for IP: %s and Account: %s\n", user_info.ip_address, user_info.username);
	}

    	// 메모리 해제
    	freePamPolicy(&pamPolicy);

	hiauth_input_data = OperateHiAuth(pamh);
	if ((hiauth_input_data->sHiAuthId == NULL || strlen (hiauth_input_data->sHiAuthPw) <= 0)  ||
		(hiauth_input_data->sHiAuthPw == NULL || strlen (hiauth_input_data->sHiAuthPw) <= 0))
	{
		nd_log (LOG_LEVEL_ERR, "HIWARE user authentication information is missing, causing the authentication task to fail");
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
	if (retval != HI_AUTH_RET_SUCCEED)
	{
		return PAM_AUTH_ERR;
		// API SERVER 연결 후 다시 처리 해야 함
	}

	return PAM_SUCCESS;

	if (g_sDataUserLoginResult == NULL || strcmp (g_sDataUserLoginResult, PAM_LOGIN_RESULT_FALSE) == 0 )
	{
		return PAM_AUTH_ERR;
	}

	if (strlen (g_sDataTemporaryAccessKey) > 0)
	{

		nd_log (NDLOG_INF, "HIWARE account authentication task with the authentication server succeeded.");

		retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &hiwareTwoFactData, sTwoFactString);
		nd_log (NDLOG_TRC, "OTP value entered by the user is [%s].", hiwareTwoFactData);
		/*
			// Send the OTP information to the API server to perform authentication.
		*/
		retval = requestTwoFactAuthToApiserver((const char *)sTwoFactString, &hi_twofactauth_ret);
		if (retval != HI_AUTH_RET_SUCCEED)
			return PAM_AUTH_ERR;

	}

	memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));

	snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_ACTUAL_NAME_FORMAT, hiauth_input_data->sHiAuthId);
	pam_putenv(pamh, sDataEnv_var);

	memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));

	snprintf (sDataEnv_var, sizeof (sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str);
	pam_putenv(pamh, sDataEnv_var);

	return 0;
}

int pam_auth_dummy_func (char * uuid_str,  struct pam_user_info user_info, pam_handle_t * pamh)
{
	int retval = 0, sock = 0, twofact_type = 0, authsvr_port = 0;
	char    *hiwareOtp = NULL, *hiwareFido = NULL;
	char  	*hiwareTwoFactData = NULL;
	char    sDataSendBuffer[MAX_SEND_DATA];
    	char    sDataRecvBuffer[MAX_RECV_DATA];
	char    sDataEnv_var[MAX_ENV_STR_LEN];
	char 	sTwoFactString[128];
	char 	sActionTypeString[128];
	char 	sDataCollocLog[MAX_STRING_LENGTH];

	struct st_hiauth_input_data    *hiauth_input_data;
	struct st_auth_result_data 	ret_data;
	struct _msg_header_ 		header = {

		.iMsgVer 	= 0,
//		.iMsgVerMin 	= 0,
		.iMsgTotalSize 	= 0
	};

	memset (&ret_data, 0x00, sizeof (struct st_auth_result_data));

	/*
		//Initialize the log storage buffer
	*/
	//initializeStorageBuffer();

	//pam_auth_dummy_func
	char * auth_server_ip   = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERIP);
        char * auth_server_port = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERPORT); 
	char * authsvr_emergency_act = get_value_from_inf(PAM_SETTING_FILE, SECTION_NM_PAM_CONF,PAM_AUTHSVR_EMERGENCY_ACTION);

	if (auth_server_port)		{
		authsvr_port = atoi (auth_server_port);
	}else				{
		authsvr_port = PAM_HIAUTH_DEFAULT_PORT;
	}


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


#ifdef _HIWARE_FUNC_TEST
	send_login_request("root", "Cosmos0610!@");

	Worker  worker;
	const char *method = "POST"; // HTTP 메서드
    	const char *url = "http://localhost:5000/sign"; // RESTful 서버 URL
	const char *urlv = "http://localhost:5000/verify";

	char rdmURL[1024];
	char loginURL[1024];
	
	const char * ip = "localhost";
	int port = 5000;
	int httpsUse = 1; // 0 -> http, 1 -> https

	MakeLoginURL 	(ip, port, loginURL, sizeof(loginURL), httpsUse);
	MakeRdmURL	(ip, port, rdmURL, sizeof(loginURL), httpsUse);

	pam_syslog (pamh, LOG_ERR, "lOGIN URL: %s, RDM URL:%s",loginURL, rdmURL); 

	const char *inputData = "{\"key\": \"value\"}";
	const char *sSessID = "your_session_id"; // 세션 ID
    	const char *m_authKey = "your_auth_key"; // API 키
	const char *data = "{\"method\": \"POST\", \"url\": \"/verify\", \"data\": \"your_data\"}";
	char * signature = GetSignature(method, url, inputData);
        //int GetRandomKey(Worker * worker)
	getRandomKey(&worker);
	pam_syslog(pamh, LOG_ERR, "GetSignature AFTER...(%s)[rand:%s/issue:%s]", signature, worker.randomKey, worker.issueKey);

	char * encPwd = encPassword("Cosmos0610!@", worker.randomKey);
	pam_syslog(pamh, LOG_ERR, "Origen: %s EncPassword:%s", "Cosmos0610!@", encPwd);

	ApiHttpRes response;
    	response.m_data = malloc(1); // 초기화
    	response.m_data[0] = '\0';
    	response.size = 0;

	if (sendPostData(data, &response, urlv, signature, sSessID, m_authKey, 1))
	{
		pam_syslog(pamh, LOG_ERR, "Response: %s\n", response.m_data);
	}
	else
	{
		pam_syslog(pamh, LOG_ERR, "Failed to send POST data.(%s)\n", response.m_data);
	}

#endif
	goto hiware_test;	
	retval = pam_check_user(user_info.username , &ret_data);
	if (retval != PAM_SUCCESS )
	{
		header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
		header.iMsgCode = PACK_MSG_CODE_REJECT_PASSWD;
		
		nd_pam_log(header, "su:auth", "Authentication failed", user_info.username, user_info.ip_address, uuid_str, sDataCollocLog,
                                        "Authentication failde for user %s from %s %s (authentication server has failed)", user_info.username ,user_info.ip_address, user_info.service);
		/*
		addStringtoStorageBuffer(sDataCollocLog);
		*/
		//sending_data_to_logger(PACK_MSG_TYPE_SSH_AUTH, PACK_MSG_CODE_REJECT_PASSWD,PACK_MSG_MAJ_VER, PACK_MSG_MIN_VER, sDataCollocLog );
		/*
		freeStorageBuffer();
		*/
		
		return PAM_AUTH_ERR;
	}

	if (ret_data.nextprocess == PAM_PROCESS_NONE)
	{
		header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                header.iMsgCode = PACK_MSG_CODE_ACCEPTED_PASSWD;

		sprintf (sActionTypeString, "%s:auth", user_info.service);
		nd_pam_log(header, sActionTypeString, "Accepted password", user_info.username, user_info.ip_address, uuid_str, sDataCollocLog,
                                        "Accepted password for user %s from %s %s", user_info.username ,user_info.ip_address, user_info.service);

		snprintf (sDataEnv_var, sizeof (sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str);
		pam_putenv(pamh, sDataEnv_var);

        	return PAM_SUCCESS;
	}

	else 
	{
		if (ret_data.nextprocess == PAM_PROCESS_HIWARE)
		{
hiware_test:
			hiauth_input_data = OperateHiAuth(pamh);
			if (hiauth_input_data == NULL)
			{
				header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                		header.iMsgCode = PACK_MSG_CODE_REJECT_HIAUTH;
				
				sprintf (sActionTypeString, "%s:auth", user_info.service);
                		nd_pam_log( header, sActionTypeString, "Authentication failed", user_info.username, user_info.ip_address, uuid_str, sDataCollocLog,
                                        "Authentication failed for %s from %s %s (input data is incorrect.)", user_info.username ,user_info.ip_address, user_info.service);

				return PAM_AUTH_ERR;
			}


			if (pam_hiware_auth_process(uuid_str, hiauth_input_data->sHiAuthId, hiauth_input_data->sHiAuthPw, &ret_data,   pamh) != PAM_SUCCESS )
			{

				header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                		header.iMsgCode = PACK_MSG_CODE_REJECT_HIAUTH;				

				sprintf (sActionTypeString, "%s:auth", user_info.service);
				nd_pam_log(header, sActionTypeString, "Authentication failed", user_info.username, user_info.ip_address, uuid_str, sDataCollocLog,
						"Authentication failed for %s from %s %s", user_info.username ,user_info.ip_address, user_info.service);

				return PAM_AUTH_ERR;
			}

			if (ret_data.nextprocess == PAM_PROCESS_NONE)
			{

				header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                		header.iMsgCode = PACK_MSG_CODE_ACCEPTED_HIAUTH;

				/*
					// setting environment variables
				*/
				snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_ACTUAL_NAME_FORMAT, hiauth_input_data->sHiAuthId);
				pam_putenv(pamh, sDataEnv_var);

				memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));

				snprintf (sDataEnv_var, sizeof (sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str);
				pam_putenv(pamh, sDataEnv_var);

				/*
					// write pam log
				*/
				sprintf (sActionTypeString, "%s:auth", user_info.service);
                		nd_pam_log(header, sActionTypeString, "Accepted hiware", user_info.username, user_info.ip_address, uuid_str, sDataCollocLog,
                                   "Accepted hiware authentication %s from %s %s", user_info.username ,user_info.ip_address, user_info.service);

				//sending_data_to_logger(PACK_MSG_TYPE_SSH_AUTH, PACK_MSG_CODE_ACCEPTED_HIAUTH ,PACK_MSG_MAJ_VER, PACK_MSG_MIN_VER, sDataCollocLog);

				return PAM_SUCCESS;
			}
			else 
			{
				if (ret_data.nextprocess == PAM_PROCESS_TWOFACT)
				{
					if (ret_data.AuthExt == PAM_EXTAUTH_OTP || ret_data.AuthExt == PAM_EXTAUTH_FIDO )
					{
						twofact_type = ret_data.AuthExt;

						sprintf (sTwoFactString, (twofact_type == PAM_EXTAUTH_OTP) ? "OTP(One-Time Password): " : "FIDO(Fast Identity Online): " );

						/*
						if (ret_data.AuthExt == PAM_EXTAUTH_OTP)
						{
							sprintf (sTwoFactString, "OTP(One-Time Password): ");
						}
						else
						{
							sprintf (sTwoFactString, "FIDO(Fast Identity Online): ");
						}
						*/
					}
					else
						return PAM_SUCCESS;


					retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &hiwareTwoFactData, sTwoFactString);
                                        if (hiwareTwoFactData != NULL )
                                        {
						memset (&ret_data, 0x00, sizeof (ret_data));
						retval = pam_twofact_auth_process(uuid_str, twofact_type, hiwareTwoFactData, &ret_data,  pamh);
						if (retval != PAM_SUCCESS )
						{
							header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                                			header.iMsgCode = PACK_MSG_CODE_REJECT_MFA;

							sprintf (sActionTypeString, "%s:auth", user_info.service);
                                			nd_pam_log(header, sActionTypeString, "Authentication failed", user_info.username, user_info.ip_address, uuid_str,sDataCollocLog,
                                        			"Two-factor Authentication failed for %s from %s %s", user_info.username ,user_info.ip_address, user_info.service);

							return PAM_AUTH_ERR;
						}			

						else
						{

							header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                                                        header.iMsgCode = PACK_MSG_CODE_ACCEPTED_MFA;						

							/*
								// setting environment variables
							*/
							snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_ACTUAL_NAME_FORMAT, hiauth_input_data->sHiAuthId);
							pam_putenv(pamh, sDataEnv_var);

							memset (sDataEnv_var, 0x00 , sizeof (sDataEnv_var));

							snprintf (sDataEnv_var, sizeof (sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str);
							pam_putenv(pamh, sDataEnv_var);

							/*
								//write pam log
							*/
							sprintf (sActionTypeString, "%s:auth", user_info.service);
                               	 			nd_pam_log(header, sActionTypeString, "Accepted two-factor", user_info.username, user_info.ip_address, uuid_str,sDataCollocLog,
                                        			"Accepted two-factor authentication %s from %s %s", user_info.username ,user_info.ip_address, user_info.service);

							//sending_data_to_logger(PACK_MSG_TYPE_SSH_AUTH, PACK_MSG_CODE_ACCEPTED_MFA ,PACK_MSG_MAJ_VER, PACK_MSG_MIN_VER, sDataCollocLog );
							return PAM_SUCCESS;
						}	
                                        }
				}

				else 
				{
					header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                                        header.iMsgCode = PACK_MSG_CODE_REJECT_PASSWD;

					sprintf (sActionTypeString, "%s:auth", user_info.service);
					nd_pam_log(header, sActionTypeString, "Authentication failed", user_info.username, user_info.ip_address, uuid_str, sDataCollocLog,
						"Two-factor Authentication failed for %s from %s %s (unexpected error has occurred.)", user_info.username ,user_info.ip_address, user_info.service);

					//sending_data_to_logger(PACK_MSG_TYPE_SSH_AUTH, PACK_MSG_CODE_REJECT_PASSWD ,PACK_MSG_MAJ_VER, PACK_MSG_MIN_VER, sDataCollocLog);

					return PAM_AUTH_ERR;
				}
			}
			
		}

		else
		{
			header.iMsgType = PACK_MSG_TYPE_SSH_AUTH;
                        header.iMsgCode = PACK_MSG_CODE_REJECT_PASSWD;

			sprintf (sActionTypeString, "%s:auth", user_info.service);
			nd_pam_log(header, sActionTypeString, "Authentication failed", user_info.username, user_info.ip_address, uuid_str,sDataCollocLog,
				"Authentication failed for %s from %s %s (unexpected error has occurred.)", user_info.username ,user_info.ip_address, user_info.service);

			//sending_data_to_logger(PACK_MSG_TYPE_SSH_AUTH, PACK_MSG_CODE_REJECT_PASSWD ,PACK_MSG_MAJ_VER, PACK_MSG_MIN_VER, sDataCollocLog);

			return PAM_AUTH_ERR;

		}
	}

	
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
	int 	retval = 0, sock = 0;
	uuid_t	uuid;
	bool 	bisAlive_server = false;
	bool 	isSuSession = false;
	struct 	st_pam_conf		pam_conf;
	struct 	pam_user_info           user_info;
	char	*uuid_str = malloc(SESSION_ID_LENGTH + 1);
	
	/*
		// log item
	*/
	char	sUserAccount[MAX_ACCOUNT_LEN];
	char 	sSwitchAccount[MAX_ACCOUNT_LEN];
	char 	sIpAddress[IPV4_BUFFER_SIZE];
	char 	sDataCollectLog[MAX_STRING_LENGTH];
	char    sDataEnv_var[MAX_ENV_STR_LEN];
	char 	sDataAgtId[16] = {0,};

	struct _msg_header_             header = {

                .iMsgVer     = 0,
                .iMsgTotalSize  = 0
        };

	setAgentId("5");

	sprintf (header.sAgentId, g_sDataAgentId);
        sprintf (header.iMsgVer, "%s", ND_PAM_VERSION);

	// Initialization of necessary variables for authentication tasks
	initializeAuthVariables();

	///TEST SRC //////////////////////////////////////////////////////////
	/////////

	char local_ip[INET_ADDRSTRLEN];
        get_local_ip(local_ip, sizeof(local_ip));

	/*
		// creat new uuid
	*/	
	generate_unique_key(uuid_str , SESSION_ID_LENGTH);

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
				strncpy (sIpAddress, info.ip, sizeof (info.ip));
				if (user_info.ip_address == NULL)
				{
					user_info.ip_address =(char*) malloc( IPV4_BUFFER_SIZE);
				}
				strncpy (user_info.ip_address, info.ip, sizeof (info.ip));
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

			PamPolicy pamPolicy = parsePamPolicy(PAM_RULE_FILE);
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

		nd_pam_sulog (header, user_info.agtAuthNo, g_sDataAgentId,  user_info.username, user_info.switchusernname, user_info.service, sIpAddress, uuid_str, sDataCollectLog );
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
                                  int argc, const char **argv) {
	system("clear");
	
	uid_t uid, switch_uid;
	gid_t gid, switch_gid;
	const char *service;
	const char *remote_ip;
	bool isConsole = 0;
	
	char ip_address[INET_ADDRSTRLEN];
	const char *tty;
	const char *username;
	char *session_id = malloc(SESSION_ID_LENGTH + 1); 
	char line[256];
	char env_var[256];
    	int found = 0;
	int retval;
	bool isSuSession = false;
	int nSuType = 0;
	char sSuType[128] = {0,};

	pam_config config = {0};

	char action_type[128];
	char message[1280];
	char szSessionKey[37];
	char szCollectLogBuff[1024];

	pam_client_info info ;

	struct _msg_header_             header = {

		.iMsgTotalSize  = 0
	};

	setAgentId("5");

	sprintf (header.sAgentId, g_sDataAgentId);
	sprintf (header.iMsgVer, "%s", ND_PAM_VERSION);

	if (read_pam_config(PAM_SETTING_FILE, &config) != 0)    {
	/*                if (strcmp(config.pam_mode,"ON") != 0 )
				return PAM_SUCCESS;
	*/		
		return PAM_SUCCESS;
	}

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

	if (session_id == NULL) {
		return PAM_BUF_ERR; // 메모리 할당 실패
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

	memset (session_id, 0x00, SESSION_ID_LENGTH);
	generate_unique_id(session_id, SESSION_ID_LENGTH);
	
	/*
		// Search for user information based on the username.
	*/
	struct passwd *pw = getpwnam(username);
	uid = pw ? pw->pw_uid : 0;
	gid = pw ? pw->pw_gid : 0;
	
	/*
		// get the tty information in the session's connection information
	*/
	pam_get_item(pamh, PAM_TTY, (const void **)&tty);
	if (tty)        {

		if (strncmp(tty, "tty", 3) == 0 )       {
			isConsole = true;
		}
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
				if (token != NULL) {
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

	/*
		// The session key set during authentication is retrieved from the environment variable.
	*/
	const char *sessionkey = pam_getenv(pamh, ENV_HIWARE_SESSIONKEY);
	const char *agtAuthNo = pam_getenv(pamh, ENV_HIWARE_AGTAUTHNO);

	header.iMsgType = isSuSession ? PACK_MSG_TYPE_SU_SESSION : PACK_MSG_TYPE_SSH_SESSION;
    	header.iMsgCode = PACK_MSG_CODE_SESSION_OPEN;

	nd_pam_session_log ( header,(char*)agtAuthNo, g_sDataAgentId,ND_PREFIX_LOGIN, session_id, (char*)username, uid, gid, isConsole, ip_address, (long)time(NULL), (char*)sessionkey, szCollectLogBuff); 
	sprintf (action_type, isSuSession ? "su:session": "sshd:session");

	if (isSuSession == true)
	{
		struct passwd *pw = getpwnam(previous_user);
		uid = pw ? pw->pw_uid : 0;
		gid = pw ? pw->pw_gid : 0;

		sprintf (message, "session opened for user %s by %s(uid=%d)", username, previous_user, uid);
	}
	else 	
	{
		sprintf (message, "session opened for user %s", username);
	}

	header.iMsgType = PACK_MSG_TYPE_SSH_SESSION;
   	header.iMsgCode = PACK_MSG_CODE_SESSION_OPEN;

	nd_pam_log(header,(char*)agtAuthNo, g_sDataAgentId,  action_type, "session_open",(char *)username, ip_address, (char*)sessionkey, szCollectLogBuff, message);
	if (set_pam_data (pamh, PAM_DATA_SESSIONID, session_id, cleanup_func) != PAM_SUCCESS)
	{
		free(session_id); 
		nd_log (NDLOG_ERR, "Failed to add session ID to PAM information.");
		return PAM_SYSTEM_ERR;
	}

	free(session_id);
	return PAM_SUCCESS;
}

/*
        //Function Definition of Linux PAM Module [pam_sm_close_session]
*/
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {

	const char *user;
	const char *remote_ip;
	char hostname[256];
	int retval, ret = 0;
	const char *tty;
	bool isConsole = false;
	uid_t uid;
    	gid_t gid;
	const char *username;
    	const char *session_id;
	const char *session_key;
	const char *service;
    	bool isSuSession = false;
	char sSuType[128] = {0,};

	const char * szClientPort;
	char ip_address[INET_ADDRSTRLEN];

	char 		action_type[128] = {0,};
	char szCollectLogBuff[1024];

	const char *previous_user;  // 바로 이전 사용자
    	const char *target_user;

	pam_client_info info ;

	struct _msg_header_ header = {

	//	.iMsgVerMaj     = 0,
	//	.iMsgVerMin     = 0,
		.iMsgTotalSize  = 0
	};

	setAgentId("5");

	sprintf (header.sAgentId, g_sDataAgentId);
	sprintf (header.iMsgVer, "%s", ND_PAM_VERSION);

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
		// Search for user information based on the username.
	*/
	struct passwd *pw = getpwnam(username);
	uid = pw ? pw->pw_uid : 0;
	gid = pw ? pw->pw_gid : 0;

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
		
		nd_pam_log(header, (char*)agtAuthNo, g_sDataAgentId, "su:session", "attempts switch",(char*)username,info.ip,(char*)sessionkey,szCollectLogBuff,
				message);


		retval = get_pam_data (pamh, "ND_CLIENT_PORT", (const void **)&szClientPort);

		if (strlen (info.port) <= 0 )
			sprintf (info.port, szClientPort);


		nd_pam_sulog (header,(char*)agtAuthNo, g_sDataAgentId,  ( char *) target_user, ( char *) previous_user, ( char *) service, info.ip, (char*)sessionkey, szCollectLogBuff);
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

	char message[128] = {0,};
	sprintf (message, "session closed for user -  %s", username);

    	nd_pam_log(header,(char*) agtAuthNo, g_sDataAgentId,  action_type, "session closed", (char*)username, ip_address,(char*)sessionkey,szCollectLogBuff,message);
	
	/*
		// Read the unique session ID stored in the environment variable after creation during authentication.
	*/
	retval = get_pam_data (pamh, PAM_DATA_SESSIONID, (const void **)&session_id);
	if (retval == PAM_SUCCESS && session_id != NULL)	{

		nd_pam_session_log (header,(char*) agtAuthNo, g_sDataAgentId,  ND_PREFIX_LOGOUT, (char*)session_id, (char *) username , uid, gid, isConsole, (char*)ip_address, (long)time(NULL), (char*)sessionkey, szCollectLogBuff);
	}
	else
	{
		nd_log (NDLOG_ERR, "Unable to retrieve the information for the registered session ID during login.");
	}

	return PAM_SUCCESS;
}

/*
        //Function Definition of Linux PAM Module [pam_sm_chauthtok]
*/
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {

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
