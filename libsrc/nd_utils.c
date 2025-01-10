
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/file.h>
#include <syslog.h>
#include <uuid/uuid.h>
#include <ctype.h>
#include <pwd.h>
#include <shadow.h>
#include <arpa/inet.h>

#include <openssl/sha.h>
#include <json-c/json.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#define _GNU_SOURCE

#include <netdb.h>

#include <sys/ioctl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <dirent.h>

#include <linux/tty.h>
#include "nd_utils.h"
#include "../common.h"
#include "nd_restapi_func.h"
#include "nd_nix_logs.h"
//#include "nd_ssl_func.h"



char* g_log_storage_buffer;
size_t g_current_length = 0;

char* Path = "/default/path";

//#include "nd_utils.h"
/*
        //Function to generate a unique value for use as a session key.
        //generate session id
*/
void generate_unique_key(char *session_id, size_t length) {

        const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for (size_t i = 0; i < length; i++) {
                int key = rand() % (int)(sizeof(charset) - 1);
                session_id[i] = charset[key];
        }
        session_id[length] = '\0'; // 문자열 종료 문자 추가
}

char* generate_unique_id() {
    uuid_t uuid;
    char uuid_str[37]; // UUID는 36자 + 널 종료
    unsigned char hash[SHA256_DIGEST_LENGTH];
    static char unique_id[UNIQUE_ID_LENGTH + 1]; // 12자리 + 널 종료

    // UUID 생성
    uuid_generate(uuid);
    uuid_unparse(uuid, uuid_str);

    // SHA-256 해시 계산
    SHA256((unsigned char*)uuid_str, strlen(uuid_str), hash);

    // 해시의 처음 12자리 추출
    for (int i = 0; i < UNIQUE_ID_LENGTH; i++) {
        sprintf(&unique_id[i * 2], "%02x", hash[i % SHA256_DIGEST_LENGTH]);
    }
    unique_id[UNIQUE_ID_LENGTH] = '\0'; // 널 종료

    return unique_id;
}

/*
        //get timestamp
*/
void get_timestamp(char *buffer, size_t size) {
        struct timespec ts;
        struct tm tm_info;

        clock_gettime(CLOCK_REALTIME, &ts);

        localtime_r(&ts.tv_sec, &tm_info);

        // yyyy-mm-dd hh:mm:ss.ffffff
        snprintf(buffer, size, "[%04d-%02d-%02d %02d:%02d:%02d.%06ld]",
             tm_info.tm_year + 1900,
             tm_info.tm_mon + 1,
             tm_info.tm_mday,
             tm_info.tm_hour,
             tm_info.tm_min,
             tm_info.tm_sec,
             ts.tv_nsec / 1000);
}

//	[STRING]

/*
        //space removal function
*/
void trim_whitespace(char *str) {
        char *end;

        /*
                // Remove leading space
        */
        while (isspace((unsigned char)*str)) str++;

        if (*str == 0) return;

        /*
                // remove trailing space
        */
        end = str + strlen(str) - 1;
        while (end > str && isspace((unsigned char)*end)) end--;

        *(end + 1) = 0;
}


/*
        //read inf fuction
*/
char *get_value_from_inf(const char *filename, const char *target_section, const char *target_key) {

        FILE *file = fopen(filename, "r");
        if (!file) {
                perror("Error opening file");
                return NULL;
        }

        char line[MAX_LINE_LENGTH];
        char current_section[MAX_KEY_LENGTH] = "";
        static char value[MAX_VALUE_LENGTH];

        while (fgets(line, sizeof(line), file)) {
                trim_whitespace(line);

                /*
                        // Ignore empty lines or comments
                */
                if (line[0] == '\0' || line[0] == ';' || line[0] == '#') {
                        continue;
                }

                /*
                        //  section syntax([Section])
                */
                if (line[0] == '[' && line[strlen(line) - 1] == ']') {
                        strncpy(current_section, line + 1, strlen(line) - 2);
                        current_section[strlen(line) - 2] = '\0';
                }
                // In case of key=value syntax
                else if (strcmp(current_section, target_section) == 0) {
                        char *equals_pos = strchr(line, '=');
                        if (equals_pos) {
                                *equals_pos = '\0';

                                char key[MAX_KEY_LENGTH];
                                strncpy(key, line, sizeof(key));
                                trim_whitespace(key);

                                /*
                                      // Return value if keys matce
                                */

                                if (strcmp(key, target_key) == 0)       {
                                        char *value = malloc(MAX_VALUE_LENGTH);
                                        if (value) {
                                                strncpy(value, equals_pos + 1, MAX_VALUE_LENGTH - 1);
                                                value[MAX_VALUE_LENGTH - 1] = '\0'; // null 종료
                                                trim_whitespace(value);
                                                fclose(file);
                                                return value; // 동적으로 할당된 메모리 반환
                                    } else      {
                                                fclose(file);
                                                return NULL; // 메모리 할당 실패
                                    }
                                }
#ifdef _OLD_SRC
                                if (strcmp(key, target_key) == 0) {
                                    strncpy(value, equals_pos + 1, sizeof(value));
                                    trim_whitespace(value);
                                    fclose(file);
                                    return value;  // return value
                                }

#endif
                        }
                }
        }

        fclose(file);
        return NULL;  //If no value is found
}


//	[config]
/*
        // read config
*/
int read_server_config(const char *section, char *ip_buffer, size_t ip_buffer_size, int *port)       {

        char *server_ip = get_value_from_inf(g_sConfFilePath, section, PAM_CONF_KEY_SERVERIP);
        char *server_port = get_value_from_inf(g_sConfFilePath, section, PAM_CONF_KEY_SERVERPORT);


        if (server_ip != NULL ) {
                strncpy (ip_buffer, server_ip, ip_buffer_size -1);
                ip_buffer[ip_buffer_size -1] = '\0';
        }else   {
                printf("Failed to read server IP\n");
                return -1;
        }

        if (server_port != NULL)        {

                *port = atoi (server_port);
        }else   {
                printf("failed to read server PORT\n");
                return -1;
        }

        return 0;
}
/*
        //
*/
void  getpamconf(struct st_pam_conf * pam_conf)
{
        char * server_pam_mode  = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,     PAM_CONF_KEY_PAM_MODE);         // PAM_MODE
        char * server_su_mode   = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,     PAM_CONF_KEY_SU_CONTROL);       // PAM_SU_CONTROL
        char * console_op_mode  = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,     PAM_CONSOLE_CONTROL);           // PAM_CONSOLE_CONTROL
        char * authsvr_linkage  = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,     PAM_AUTHSVR_LINKAGE);           // PAM_AUTHSVR_LINKAGE
        char * authsvr_emergency_act = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,PAM_AUTHSVR_EMERGENCY_ACTION);  // PAM_AUTHSVR_EMERGENCY_ACTION
        char * authsvr_timeout  = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,     PAM_AUTHSVR_TIMEOUT);           // PAM_AUTHSVR_TIMEOUT

        char * auth_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERIP);          // SERVER_IP
        char * auth_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERPORT);        // SERVER_PORT
        char * auth_server_use  = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERUSE);         // SERVER_USE

        /*
                //
        */
        if (server_pam_mode)    {
 
		pam_conf->pam_operate_mode = (strcasecmp (server_pam_mode, SET_MODE_ON) == 0 ) ? 1 : 0;

        }else                   {
                pam_conf->pam_operate_mode = MODE_OFF;
        }

        /*
                //
        */
        if (server_su_mode)     {
                pam_conf->su_operate_mode = atoi (server_su_mode);

        }else                   {
                pam_conf->su_operate_mode = OPER_MODE_OFF;
        }

        /*
                //
        */
        if (console_op_mode)    {
                strncpy (pam_conf->console_operate_mode, console_op_mode, MAX_OPMODE_LEN);
                pam_conf->console_operate_mode[MAX_OPMODE_LEN -1] = '\0';
        }else                   {
                strncpy (pam_conf->console_operate_mode, SET_MODE_OFF, 4);
        }

        /*
                //
        */
        if (authsvr_linkage)    {
                strncpy (pam_conf->authsvr_linkage, authsvr_linkage, MAX_OPMODE_LEN);
                pam_conf->authsvr_linkage[MAX_OPMODE_LEN -1] = '\0';

        }else                   {
                strncpy (pam_conf->console_operate_mode, SET_MODE_OFF, 4);
        }

        /*
                //
        */
        if (authsvr_emergency_act)      {
                strncpy (pam_conf->authsvr_emergency_act, authsvr_emergency_act, MAX_EMERGENCYMODE_LEN);
                pam_conf->authsvr_emergency_act[MAX_EMERGENCYMODE_LEN] = '\0';
        }else                   {
                strncpy (pam_conf->authsvr_emergency_act, SET_MODE_BYPASS, MAX_EMERGENCYMODE_LEN);
        }

        /*
                //
        */
        if (authsvr_timeout)    {
                pam_conf->authsvr_timeout = atoi (authsvr_timeout);
        }else                   {
                pam_conf->authsvr_timeout = DEFAULT_TIMEOUT;
        }

        /*
                //
        */
        if (auth_server_ip)     {
                strncpy (pam_conf->auth_ip, auth_server_ip, IPV4_BUFFER_SIZE);
                pam_conf->auth_ip[IPV4_BUFFER_SIZE -1] = '\0';
        }else                   {
                strncpy (pam_conf->auth_ip, "0.0.0.0", IPV4_BUFFER_SIZE);
        }

        if (auth_server_port)   {
                pam_conf->auth_port = atoi (auth_server_port);
        }else                   {
                pam_conf->auth_port = PAM_HIAUTH_DEFAULT_PORT;
        }

        nd_log (LOG_LEVEL_INFO, "====================================================================");
        nd_log (LOG_LEVEL_INFO, "[read from the configuration file]");
        nd_log (LOG_LEVEL_INFO, "--------------------------------------------------------------------");
        nd_log (LOG_LEVEL_INFO, " * setting file paht : %s", g_sConfFilePath);
        nd_log (LOG_LEVEL_INFO, "--------------------------------------------------------------------");
        nd_log (LOG_LEVEL_INFO, "\t- [section :PAM_CONF] PAM_MODE                       :%s",server_pam_mode ? server_pam_mode : "Could not read");
        nd_log (LOG_LEVEL_INFO, "\t- [section :PAM_CONF] PAM_SU_CONTROL                 :%s", server_su_mode ? server_su_mode : "Could not read");
        nd_log (LOG_LEVEL_INFO, "\t- [section :PAM_CONF] PAM_CONSOLE_CONTROL            :%s", console_op_mode ? console_op_mode : "Could not read");
        nd_log (LOG_LEVEL_INFO, "\t- [section :PAM_CONF] PAM_AUTHSVR_LINKAGE            :%s", authsvr_linkage ? authsvr_linkage : "Could not read");
        nd_log (LOG_LEVEL_INFO, "\t- [section :PAM_CONF] PAM_AUTHSVR_EMERGENCY_ACTION   :%s", authsvr_emergency_act ? authsvr_emergency_act : "Could not read");
        nd_log (LOG_LEVEL_INFO, "\t- [section :PAM_CONF] PAM_AUTHSVR_TIMEOUT            :%s", authsvr_timeout ? authsvr_timeout : "Could not read");
        nd_log (LOG_LEVEL_INFO, "\t- [section :HIAUTH_CONF] SERVER_IP                   :%s", auth_server_ip ? auth_server_ip : "Could not read");
        nd_log (LOG_LEVEL_INFO, "\t- [section :HIAUTH_CONF] SERVER_PORT                 :%s", auth_server_port ? auth_server_port : "Could not read");
        nd_log (LOG_LEVEL_INFO, "\t- [section :HIAUTH_CONF] SERVER_USE                  :%s", auth_server_use ? auth_server_use : "Could not read");

        nd_log (LOG_LEVEL_INFO, "====================================================================");
}



//	[network]
/*
        //
        //socket connection function
*/
int connect_to_server(int *sock, const char *section) {

        char szMsg[1024] = {0,};
        char server_ip[16];
        int server_port;
	struct timeval timeout;

        /*
                // Read server settings
        */
        if (read_server_config(section, server_ip, sizeof(server_ip), &server_port) != 0) {
                return -1;
        }

        struct sockaddr_in server;

        /*
                // create socket
        */
        *sock = socket(AF_INET, SOCK_STREAM, 0);
        if (*sock == -1) {
                sprintf(szMsg,"Failed socket creation - %s", strerror(errno));
                return -2;
        }

	//
	// 2025-01-07
	// Set socket to non-blocking mode
        if (set_non_blocking(*sock) < 0) {
                perror("[ERR] Failed to set non-blocking mode");
                close(sock);
                return -3;
        }

	// Configure server information
        memset(&server, 0, sizeof(server));


        /*
                // Setting server address
        */
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port);
        server.sin_addr.s_addr = inet_addr(server_ip);

        /*
                // connect server
        */
        //if (connect(*sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
	if (connect(*sock, (struct sockaddr *)&server, sizeof(server)) < 0 && errno != EINPROGRESS) {

                perror("connect failed.");
                close(*sock);
                return -4;
        }

	//
        // 2025-01-07
	// Use select() to check if the connection is complete
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(*sock, &write_fds);

        timeout.tv_sec = 0;        // Timeout in seconds
        timeout.tv_usec = 500000;  // Timeout in microseconds (500ms)

	if (select(*sock + 1, NULL, &write_fds, NULL, &timeout) > 0) {
                int error = 0;
                socklen_t len = sizeof(error);

                // Check the socket state
                if (getsockopt(*sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                        close(sock);
                        return 1; // Connection successful
                }
        }

	// Connection failed
        close(*sock);

        return -1; // success
}


/*
        // data transfer function
*/
int send_data(int sock, const char *data)       {

        if (send(sock, data, strlen(data), 0) < 0)      {
                //fprintf(stderr, "Data transfer failure: %s\n", strerror(errno));
                return -1;
        }
        return 0; // success
}

int send_data_v2(int sock, const char *data, size_t data_length)       {

        if (send(sock, data, data_length, 0) < 0)      {
                //fprintf(stderr, "Data transfer failure: %s\n", strerror(errno));
                return -1;
        }
        return 0; // success
}



/*
        //data reception function
*/
int receive_data(int sock, char *buffer, size_t buffer_size)    {

        fd_set readfds;
        struct timeval timeout;
        int timeout_sec = 0;

        //PAM_AUTHSVR_TIMEOUT
        char * authsvr_timeout  = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,     PAM_AUTHSVR_TIMEOUT);
        if (authsvr_timeout)    {
                timeout_sec = atoi (authsvr_timeout);
        }else                   {
                timeout_sec = DEFAULT_TIMEOUT;
        }

        /*
                // Add the socket to the read set
        */
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        /*
                // setting timeout
        */
        timeout.tv_sec  = timeout_sec;
        timeout.tv_usec = 0;

        /*
                // call select function
        */
        int result = select(sock + 1, &readfds, NULL, NULL, &timeout);
        if (result < 0)         {
                return -1;
        }

        else if (result == 0)   {
                return -1;
        }

        /*
                // recv data
        */
        ssize_t bytes_received = recv(sock, buffer, buffer_size - 1, 0);
        if (bytes_received < 0) {
                fprintf(stderr, "Receive failure data : %s\n", strerror(errno));
                return -1;
        }
        buffer[bytes_received] = '\0';
        return 0; // success
}

int set_non_blocking(int sock) 		{

	int flags = fcntl(sock, F_GETFL, 0);
    	if (flags < 0) return -1;
    	return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

/*
        //
*/
int check_server_connection(const char *ip, int port)   {

       	int sock;
	struct sockaddr_in server;
	struct timeval timeout;

	// Create a socket
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("[ERR] Failed to create socket descriptor");
		return 0;
	}

	// Set socket to non-blocking mode
	if (set_non_blocking(sock) < 0) {
		perror("[ERR] Failed to set non-blocking mode");
		close(sock);
		return 0;
	}

	// Configure server information
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &server.sin_addr) <= 0) {
		perror("[ERR] Invalid IP address");
		close(sock);
		return 0;
	}

	// Attempt to connect to the server
	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0 && errno != EINPROGRESS) {
		perror("[ERR] Connection attempt failed");
		close(sock);
		return 0;
	}

	// Use select() to check if the connection is complete
	fd_set write_fds;
	FD_ZERO(&write_fds);
	FD_SET(sock, &write_fds);

	timeout.tv_sec = 0;        // Timeout in seconds
	timeout.tv_usec = 500000;  // Timeout in microseconds (500ms)

	if (select(sock + 1, NULL, &write_fds, NULL, &timeout) > 0) {
		int error = 0;
		socklen_t len = sizeof(error);

		// Check the socket state
		if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
		    	close(sock);
		    	return 1; // Connection successful
		}
	}

	// Connection failed
	close(sock);
	return 0;
}

//	[user item]
/*
        // get encrypted password
*/
const char* get_encrypted_password_from_shadow_v2(const char* username)         {

        struct spwd *sp = getspnam(username);
        if (sp == NULL)         {
                return NULL;
        }
        return sp->sp_pwdp;
}

/*
        // get encrypted password
        // This is a function that retrieves a specific user's password hash from the /etc/shadow file.
*/
const char* get_encrypted_password_from_shadow(const char* user)        {

        static char encrypted_passwd[MAX_LINE_LENGTH];
        struct spwd *sp;
        struct passwd *pw;
        char *shadow_path = "/etc/shadow";
        FILE *shadow_file;
        char line[MAX_LINE_LENGTH];
        char *username;
        char *password_hash;

        /*
                // /etc/shadow open file
        */
        shadow_file = fopen(shadow_path, "r");
        if (!shadow_file) {
                //syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
                return NULL;
        }

        while (fgets(line, sizeof(line), shadow_file)) {

                username = strtok(line, ":");
                password_hash = strtok(NULL, ":");

                if (username && password_hash && strcmp(username, user) == 0) {
                    strncpy(encrypted_passwd, password_hash, sizeof(encrypted_passwd) - 1);
                    encrypted_passwd[sizeof(encrypted_passwd) - 1] = '\0'; // null-terminate
                    fclose(shadow_file);
                    return encrypted_passwd;
                }
        }

        fclose(shadow_file);
        return NULL;
}

/*
        //JSON . json-c
*/
char *create_pam_archivelogdate_using_JSON(struct _archive_log logitem)
{
	struct timeval tv;
 	struct tm *tm_info;

	time_t now;
    	time(&now);

	json_object *jobj	= json_object_new_object();
	json_object *jitems     = json_object_new_object();

	gettimeofday(&tv, NULL);
	tm_info = localtime(&tv.tv_sec);

	char buffer[30], sDataTime[ND_TIME_MAX_LEN];
	strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", tm_info);
	
	//snprintf(sDataTime, sizeof (sDataTime), "%s.%03ld+0900", buffer, tv.tv_usec / 1000);
	snprintf (sDataTime, sizeof (sDataTime), "%ld", now);
	
	if (strcmp (logitem.pamCertDtlCode, "01") == 0 || strcmp (logitem.pamCertDtlCode, "03") == 0 /*|| strcmp (logitem.pamCertDtlCode, "04") == 0*/)
		json_object_object_add(jobj, "svrConnStartDttm", json_object_new_string(sDataTime ));
	else
		json_object_object_add(jobj, "svrConnStartDttm", json_object_new_string("" ));

	if (strcmp (logitem.pamCertDtlCode, "02") == 0 || strcmp (logitem.pamCertDtlCode, "04") == 0 )
		json_object_object_add(jobj, "svrConnEndDttm", json_object_new_string(sDataTime ));
	else
		json_object_object_add(jobj, "svrConnEndDttm", json_object_new_string("" ));

	json_object_object_add(jobj, "svrConnRstTpCode", json_object_new_string(logitem.svrConnRstTpCode ));
	json_object_object_add(jobj, "svrConnFailRsnCode", json_object_new_string(logitem.svrConnFailRsnCode ));
	json_object_object_add(jobj, "agtNo", json_object_new_string(logitem.agtNo ));
	json_object_object_add(jobj, "agtConnFormTpCode", json_object_new_string(logitem.agtConnFormTpCode ));
	json_object_object_add(jobj, "agtAuthNo", json_object_new_string(logitem.agtAuthNo ));
	json_object_object_add(jobj, "portNo", json_object_new_int(g_nDataSshPort));
	json_object_object_add(jobj, "userIp", json_object_new_string(logitem.userIp ));

	json_object_object_add(jobj, "securStepNo", json_object_new_string(logitem.securStepNo )); 	

	json_object_object_add(jobj, "svrConnSessKeyNo", json_object_new_string(logitem.svrConnSessKey ));
	json_object_object_add(jobj, "connAcctId", json_object_new_string(logitem.connAcctId ));
	json_object_object_add(jobj, "switchAcctId", json_object_new_string(logitem.switchAcctId ));
	json_object_object_add(jobj, "pamAgtAuthNo", json_object_new_string(logitem.pamAgtAuthNo ));
	json_object_object_add(jobj, "userNo", json_object_new_string(logitem.userNo));
	json_object_object_add(jobj, "pamCertDtlCode", json_object_new_string(logitem.pamCertDtlCode ));
	json_object_object_add(jobj, "pamCertDtlAuthCode", json_object_new_string(logitem.pamCertDtlAuthCode ));

	json_object *connCert = json_object_new_object();

	json_object_object_add(connCert, "certTpCode", json_object_new_string(logitem.certTpCode ));
	json_object_object_add(connCert, "certAppTpCode", json_object_new_string(logitem.certAppTpCode ));
	json_object_object_add(connCert, "certSucesFailYn", json_object_new_string(logitem.certSucesFailYn ));
	json_object_object_add(connCert, "certStepSeqNo", json_object_new_string(logitem.certStepSeqNo ));
	
	json_object_object_add(jobj, "connCert", connCert);	

	/*
                // convert to JSON string
        */

	const char *json_string = json_object_to_json_string(jobj);

	/*
                // copy and return JSON string
        */
        char *result = strdup(json_string);

	json_object_put(jobj);

	return result;
}

/*
	//JSON . json-c
*/
char *create_pamlogdata_using_JSON(const char * agtauth_no, const char * agtId,  const char* action_type, const char* session_status, const char* account, const char* ipaddr, const char* session_key, const char* message)
{
	int /*authsvr_port = 0,*/ retval = 0;

	const char *userNumber = getenv(ENV_HIWARE_USER_NUMBER);
	

	/*
		// create json object
	*/
	json_object *jobj 	= json_object_new_object();
    	json_object *jbody 	= json_object_new_object();
	json_object *jitems 	= json_object_new_object();

	/*
		// add data to item object
	*/
	if (agtauth_no)
		json_object_object_add(jitems, "agtauth_no", json_object_new_string(agtauth_no));
	else
		json_object_object_add(jitems, "agtauth_no", json_object_new_string(""));

	if (agtId)
                json_object_object_add(jitems, "agent_id", json_object_new_string(agtId));
        else
                json_object_object_add(jitems, "agent_id", json_object_new_string(""));

	if (userNumber)
		json_object_object_add(jitems, "userNumber", json_object_new_string(userNumber));
	else 
		json_object_object_add(jitems, "userNumber", json_object_new_string(""));

	//json_object_object_add(jitems, "sshPortNumber", json_object_new_int(get_ssh_port()));

	if (action_type)
		json_object_object_add(jitems, "action_type", json_object_new_string(action_type));
	else
		json_object_object_add(jitems, "action_type", json_object_new_string(""));

	if (session_status)
    		json_object_object_add(jitems, "session_status", json_object_new_string(session_status));
	else
		json_object_object_add(jitems, "session_status", json_object_new_string(""));

	if (account)
    		json_object_object_add(jitems, "account", json_object_new_string(account));
	else
		json_object_object_add(jitems, "account", json_object_new_string(""));

	if (ipaddr)
		json_object_object_add(jitems, "ipaddr", json_object_new_string(ipaddr));
	else
		json_object_object_add(jitems, "ipaddr", json_object_new_string(""));

	if (session_key)
		json_object_object_add(jitems, "session_key", json_object_new_string(session_key));
	else
		json_object_object_add(jitems, "session_key", json_object_new_string(""));

	if (message)
		json_object_object_add(jitems, "message", json_object_new_string(message));
	else
		json_object_object_add(jitems, "message", json_object_new_string(""));

	/*
		// add items to body object
	*/
	json_object_object_add(jbody, "name", json_object_new_string("pam_log"));
    	json_object_object_add(jbody, "items", jitems);	

	/*
		// add body to finally JSON object
	*/
	json_object_object_add(jobj, "body", jbody);

	/*	
		// convert to JSON string 
	*/
	const char *json_string = json_object_to_json_string(jobj);

	/*
                // copy and return JSON string
        */
        char *result = strdup(json_string);

	json_object_put(jobj);

	return result;
}

/*
        //JSON . jsnon-c
*/
char *create_sessionlogdata_using_JSON(const char * agtauth_no, const char * agtId,  const char* prefix, const char* session_id, const char* account, int uid, int gid, int isconsole, const char* ipaddr, long time, const char* session_key)
{
	//int authsvr_port = 0, retval = 0;

	/*
			// create json object
	*/
	json_object *jobj       = json_object_new_object();
	json_object *jbody      = json_object_new_object();
	json_object *jitems     = json_object_new_object();

	/*
			// add data to item object
	*/
	if (agtauth_no)
                json_object_object_add(jitems, "agtauth_no", json_object_new_string(agtauth_no));
        else
                json_object_object_add(jitems, "agtauth_no", json_object_new_string(""));

        if (agtId)
                json_object_object_add(jitems, "agent_id", json_object_new_string(agtId));
        else
                json_object_object_add(jitems, "agent_id", json_object_new_string(""));

        if (prefix)
                json_object_object_add(jitems, "prefix", json_object_new_string(prefix));
        else
                json_object_object_add(jitems, "prefix", json_object_new_string(""));

        if (session_id)
                json_object_object_add(jitems, "session_id", json_object_new_string(session_id));
        else
                json_object_object_add(jitems, "session_id", json_object_new_string(""));

        if (account)
                json_object_object_add(jitems, "account", json_object_new_string(account));
        else
                json_object_object_add(jitems, "account", json_object_new_string(""));

        json_object_object_add(jitems, "uid", json_object_new_int(uid));

        json_object_object_add(jitems, "gid", json_object_new_int(gid));

        json_object_object_add(jitems, "isconsole", json_object_new_int(isconsole));
	
	if (ipaddr)
		json_object_object_add(jitems, "ipaddr", json_object_new_string(ipaddr));
	else
		json_object_object_add(jitems, "ipaddr", json_object_new_string(""));

	json_object_object_add(jitems, "time", json_object_new_int64(time));

	if (session_key)
		json_object_object_add(jitems, "session_key", json_object_new_string(session_key));
	else
		json_object_object_add(jitems, "session_key", json_object_new_string(""));

	/*
			// add items to body object
	*/
	json_object_object_add(jbody, "name", json_object_new_string("session_log"));
	json_object_object_add(jbody, "items", jitems);

	/*
			// add body to finally JSON object
	*/
	json_object_object_add(jobj, "body", jbody);

	/*
			// convert to JSON string
	*/
	const char *json_string = json_object_to_json_string(jobj);

	/*
			// copy and return JSON string
	*/
	char *result = strdup(json_string);

	json_object_put(jobj);

	return result;

}

/*
        //JSON . json-c
*/
char *create_sulogdata_using_JSON(const char * agtauth_no, const char * agtId,  const char* account, const char* switch_account, const char* su_command, const char* client_ip, long time, const char* session_key)
{
	//int authsvr_port = 0, retval = 0;

	/*
			// create json object
	*/
	json_object *jobj       = json_object_new_object();
	json_object *jbody      = json_object_new_object();
	json_object *jitems     = json_object_new_object();

	/*
			// add data to item object
	*/
	if (agtauth_no)
                json_object_object_add(jitems, "agtauth_no", json_object_new_string(agtauth_no));
	else
			json_object_object_add(jitems, "agtauth_no", json_object_new_string(""));

	if (agtId)
			json_object_object_add(jitems, "agent_id", json_object_new_string(agtId));
	else
			json_object_object_add(jitems, "agent_id", json_object_new_string(""));

	if (account)
			json_object_object_add(jitems, "account", json_object_new_string(account));
	else
			json_object_object_add(jitems, "account", json_object_new_string(""));

	if (switch_account)
			json_object_object_add(jitems, "switch_account", json_object_new_string(switch_account));
	else
			json_object_object_add(jitems, "switch_account", json_object_new_string(""));

	if (su_command)
			json_object_object_add(jitems, "su_command", json_object_new_string(su_command));
	else
			json_object_object_add(jitems, "su_command", json_object_new_string(""));


	if (client_ip)
			json_object_object_add(jitems, "client_ip", json_object_new_string(client_ip));
	else
			json_object_object_add(jitems, "client_ip", json_object_new_string(""));

	json_object_object_add(jitems, "time", json_object_new_int64(time));

	if (session_key)
			json_object_object_add(jitems, "session_key", json_object_new_string(session_key));
	else
			json_object_object_add(jitems, "session_key", json_object_new_string(""));

	/*
			// add items to body object
	*/
	json_object_object_add(jbody, "name", json_object_new_string("su_log"));
	json_object_object_add(jbody, "items", jitems);

	/*
			// add body to finally JSON object
	*/
	json_object_object_add(jobj, "body", jbody);

	/*
			// convert to JSON string
	*/
	const char *json_string = json_object_to_json_string(jobj);

	/*
			// copy and return JSON string
	*/
	char *result = strdup(json_string);

	json_object_put(jobj);

	return result;

}

/*
        //
*/
int sending_data_to_logger(char * sAgentId, unsigned char iType, unsigned char iCode, char *iVer/*,unsigned char iVerMin, */,char * data)
{
	int authsvr_port = 0, retval = 0, sock = 0;
	// Create and initialize the header
	struct _msg_header_ header = {
		.sAgentId       = sAgentId,
                .iMsgType       = iType,
                .iMsgCode       = iCode,
                .iMsgTotalSize  = htonl( strlen (data)),
    	};

	sprintf ((char*)header.iMsgVer, "%s", ND_PAM_VERSION);
	size_t total_size = sizeof(struct _msg_header_) + strlen(data);

/*
	sprintf ((char*)header.sAgentId, "%s", sAgentId);
	sprintf ((char*)header.iMsgVer, "%s", ND_PAM_VERSION);

	size_t data_size = strlen(data);
	size_t total_size = sizeof(struct _msg_header_) + data_size;
	header.iMsgTotalSize = data_size;//total_size;
*/
	// Allocate buffer for header + data
	char *sendbuff = (char *)malloc(total_size);
	if (sendbuff == NULL) {
		return -1;  // Memory allocation failed
	}

	// Copy the header and data into the buffer
	memcpy(sendbuff, &header, sizeof(struct _msg_header_));
	memcpy(sendbuff + sizeof(struct _msg_header_), data,  strlen(data));

	// Move pointer to start of data (after header)
	//char *data_ptr = sendbuff + sizeof(struct _msg_header_);
        char * auth_server_ip   = get_value_from_inf(g_sConfFilePath, "HILOGER_CONF", PAM_CONF_KEY_SERVERIP);
        char * auth_server_port = get_value_from_inf(g_sConfFilePath, "HILOGER_CONF", PAM_CONF_KEY_SERVERPORT);

        if (auth_server_port)           {
                authsvr_port = atoi (auth_server_port);
        }else                           {
                authsvr_port = PAM_HIAUTH_DEFAULT_PORT;
        }

        retval = connect_to_server(&sock, "HILOGER_CONF");
        if (retval != 0)
        {
                close(sock);
                return -1;
        }
        else
        {
                send_data_v2 (sock, sendbuff, total_size);
        }
        free (sendbuff);
        close (sock);

	return 0;
}

int initializeAuthVariables(void)
{
	char * auth_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERIP);
    char * auth_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERPORT);
	char * auth_use_ssl	= get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_AUTHSVR_USESSL);

	MakeRdmURL(auth_server_ip, atoi (auth_server_port), g_sDataRandomUrl, sizeof (g_sDataRandomUrl), (strcmp (auth_use_ssl,CONF_VALUE_YES) == 0)?1:0);
	MakeLoginURL(auth_server_ip, atoi (auth_server_port), g_sDataSystemLoginUrl, sizeof (g_sDataSystemLoginUrl), (strcmp(auth_use_ssl, CONF_VALUE_YES) == 0)?1:0);

	nd_log (LOG_LEVEL_INFO, "====================================================================");
	nd_log (LOG_LEVEL_INFO, "[API SERVER information read from the configuration file]");
	nd_log (LOG_LEVEL_INFO, "--------------------------------------------------------------------");
	nd_log (LOG_LEVEL_INFO, " * setting file paht : %s", g_sConfFilePath);
	nd_log (LOG_LEVEL_INFO, "--------------------------------------------------------------------");
	nd_log (LOG_LEVEL_INFO, "\t- <api server> ip address   :%s", auth_server_ip ? auth_server_ip : "Could not read");
	nd_log (LOG_LEVEL_INFO, "\t- <api server> ip port      :%s", auth_server_port ? auth_server_port : "Could not read");
	nd_log (LOG_LEVEL_INFO, "\t- <api server> ssl use flag :%s", auth_use_ssl ? auth_use_ssl : "Could not read");

	nd_log (LOG_LEVEL_INFO, "--------------------------------------------------------------------");
	nd_log (LOG_LEVEL_INFO, "[API SERVER ENDPOINT information]");
	nd_log (LOG_LEVEL_INFO, "\t- Request Random url        :%s", g_sDataRandomUrl);
	nd_log (LOG_LEVEL_INFO, "\t- request SystemLogin url   :%s", g_sDataSystemLoginUrl);
	nd_log (LOG_LEVEL_INFO, "====================================================================");

	if (!auth_server_ip)            nd_log (LOG_LEVEL_ERR, "[PREFIX-ERR CODE] Failed to get api server ip address.");
	if (!auth_server_port)          nd_log (LOG_LEVEL_ERR, "[PREFIX-ERR CODE] Failed to get api server port.");
	if (strlen(g_sDataRandomUrl) <= 0)          nd_log (LOG_LEVEL_ERR, "[PREFIX-ERR CODE] Failed to get url for random number request.");
	if (strlen(g_sDataSystemLoginUrl) <= 0)     nd_log (LOG_LEVEL_ERR, "[PREFIX-ERR CODE] Failed to get url for system login request.");
        
	return 0;
}


#ifdef _MOVE_SRC
void MakeRdmURL(const char *ip, int port, char *rdmURL, size_t rdmURLSize, int httpsUse)        {

        // Buffer declaration for creating a URL
        char url[1024]; // Set the buffer to an appropriate size (adjust the size if necessary)

        // Determine whether to use HTTP or HTTPS
        if (httpsUse == 0) {
                snprintf(url, sizeof(url), "http://%s:%d%s", ip, port, STRING_RANDOM_KEY_URI);
        } else {
                snprintf(url, sizeof(url), "https://%s:%d%s", ip, port, STRING_RANDOM_KEY_URI);
        }

        // Copy the generated URL to rdmURL
        strncpy(rdmURL, url, rdmURLSize - 1);
        rdmURL[rdmURLSize - 1] = '\0';  // Add a null termination character at the end
}

void MakeLoginURL(const char *ip, int port, char *loginURL, size_t loginURLSize, int httpsUse)  {

        // Buffer declaration for creating a URL
        char url[1024]; // Set the buffer to an appropriate size (adjust the size if necessary)

        // Determine whether to use HTTP or HTTPS
        if (httpsUse == 0) {
                snprintf(url, sizeof(url), "http://%s:%d%s", ip, port, STRING_LOGIN_URI);
        } else {
                snprintf(url, sizeof(url), "https://%s:%d%s", ip, port, STRING_LOGIN_URI);
        }

        // Copy the generated URL to rdmURL
        strncpy(loginURL, url, loginURLSize - 1);
        loginURL[loginURLSize - 1] = '\0';  // Add a null termination character at the end
}

#endif //_MOVE_SRC

char * getAgentId()
{
	return g_sDataAgentId;
}

void setAgentId(char * id)
{
	sprintf (g_sDataAgentId, "%s", id );
}
/*
void parse_json(const char *filename) {

	FILE *file = fopen(filename, "r");
    	if (!file) {
        	perror("Unable to open file");
        	return;
    	}

    	char buffer[1024];
    	struct json_object *parsed_json;
    	struct json_object *ipaddress;
    	struct json_object *accounts;
    	struct json_object *agent_id;
    	struct json_object *privileges_id;

    	while (fgets(buffer, sizeof(buffer), file)) {
        	// JSON 객체 파싱
        	parsed_json = json_tokener_parse(buffer);
        	if (parsed_json == NULL) {
            	fprintf(stderr, "Error parsing JSON\n");
            	continue;
        }

        // JSON 필드 읽기
        json_object_object_get_ex(parsed_json, "ipaddress", &ipaddress);
        json_object_object_get_ex(parsed_json, "accounts", &accounts);
        json_object_object_get_ex(parsed_json, "agent_id", &agent_id);
        json_object_object_get_ex(parsed_json, "Privileges_id", &privileges_id);

        // 결과 출력
        for (size_t i = 0; i < json_object_array_length(accounts); i++) {
            struct json_object *account = json_object_array_get_idx(accounts, i);
        }

        // JSON 객체 메모리 해제
        json_object_put(parsed_json);
    }

    fclose(file);
}
*/

void parse_json(const char *filename) {

	FILE *file = fopen(filename, "r");
	if (!file) {
		return;
	}

	// 파일 전체 내용을 읽기
	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	char *buffer = malloc(file_size + 1);
	fread(buffer, 1, file_size, file);
	buffer[file_size] = '\0'; // null-terminate the string

	struct json_object *parsed_json = json_tokener_parse(buffer);
	if (parsed_json == NULL) {
		fprintf(stderr, "Error parsing JSON\n");
		free(buffer);
		fclose(file);
		return;
	}

	// JSON 배열의 길이
	size_t array_length = json_object_array_length(parsed_json);
	for (size_t j = 0; j < array_length; j++) {
		struct json_object *json_object = json_object_array_get_idx(parsed_json, j);
		struct json_object *ipaddress;
		struct json_object *accounts;
		struct json_object *agent_id;
		struct json_object *privileges_id;

		// JSON 필드 읽기
		json_object_object_get_ex(json_object, "ipaddress", &ipaddress);
		json_object_object_get_ex(json_object, "accounts", &accounts);
		json_object_object_get_ex(json_object, "agent_id", &agent_id);
		json_object_object_get_ex(json_object, "Privileges_id", &privileges_id);
	}

	// 메모리 해제
	json_object_put(parsed_json);
	free(buffer);
	fclose(file);
}

PamPolicy parsePamPolicy(const char *filename) {

	PamPolicy pamPolicy = {NULL, 0};
	struct json_object *parsed_json;
	struct json_object *ruleList;
	struct json_object *rule;
	struct json_object *ipList;
	struct json_object *account;
	size_t n_rules, i, j;

	// JSON 파일 읽기
	FILE *file = fopen(filename, "r");
	if (!file) {
		perror("Unable to open file");
		return pamPolicy;
	}

	fseek(file, 0, SEEK_END);
	long length = ftell(file);
	fseek(file, 0, SEEK_SET);
	char *data = malloc(length);
	fread(data, 1, length, file);
	fclose(file);

	// JSON 파싱
	parsed_json = json_tokener_parse(data);
	free(data);

	json_object_object_get_ex(parsed_json, "pamPolicy", &ruleList);
	json_object_object_get_ex(ruleList, "ruleList", &ruleList);
	n_rules = json_object_array_length(ruleList);

	pamPolicy.rules = malloc(n_rules * sizeof(Rule));
	pamPolicy.ruleCount = n_rules;

	for (i = 0; i < n_rules; i++) {
		rule = json_object_array_get_idx(ruleList, i);
		// action과 logging 값을 가져올 때 json_object_get_int 사용
		pamPolicy.rules[i].priNo = json_object_get_int(json_object_object_get(rule, "priNo"));		
		pamPolicy.rules[i].agtAuthNo = json_object_get_string(json_object_object_get(rule, "agtAuthNo"));

		pamPolicy.rules[i].action = json_object_get_int(json_object_object_get(rule, "action"));
		pamPolicy.rules[i].logging = json_object_get_int(json_object_object_get(rule, "logging"));

		json_object_object_get_ex(rule, "ipList", &ipList);
		pamPolicy.rules[i].ipCount = json_object_array_length(ipList);
		pamPolicy.rules[i].ipList = malloc(pamPolicy.rules[i].ipCount * sizeof(char *));
		for (j = 0; j < (size_t)pamPolicy.rules[i].ipCount; j++) {
		    pamPolicy.rules[i].ipList[j] = strdup(json_object_get_string(json_object_array_get_idx(ipList, j)));
		}

		json_object_object_get_ex(rule, "account", &account);
		pamPolicy.rules[i].accountCount = json_object_array_length(account);
		pamPolicy.rules[i].account = malloc(pamPolicy.rules[i].accountCount * sizeof(char *));
		for (j = 0; j < (size_t) pamPolicy.rules[i].accountCount; j++) {
		    pamPolicy.rules[i].account[j] = strdup(json_object_get_string(json_object_array_get_idx(account, j)));
		}
	}

	json_object_put(parsed_json); // JSON 객체 메모리 해제
	return pamPolicy;
}

void freePamPolicy(PamPolicy *pamPolicy) 	{

	for (int i = 0; i < pamPolicy->ruleCount; i++) 		{
		for (int j = 0; j < pamPolicy->rules[i].ipCount; j++) 		{
		    	free(pamPolicy->rules[i].ipList[j]);
		}
		free(pamPolicy->rules[i].ipList);

		for (int j = 0; j < pamPolicy->rules[i].accountCount; j++) 	{
		    	free(pamPolicy->rules[i].account[j]);
		}
		free(pamPolicy->rules[i].account);
	}
	free(pamPolicy->rules);
}


Rule *isPamPolicyMatched(const PamPolicy *pamPolicy, const char *ipaddr, const char *account) 	{

	for (int i = 0; i < pamPolicy->ruleCount; i++) {
		const Rule *rule = &pamPolicy->rules[i];

		// IP 주소가 규칙의 IP 리스트에 있는지 확인
		int ipMatched = 0;
		for (int j = 0; j < rule->ipCount; j++) {
			if (strcmp(rule->ipList[j], ipaddr) == 0) {
				ipMatched = 1;
				break;
			}
		}

		// 계정이 규칙의 계정 리스트에 있는지 확인
		int accountMatched = 0;
		for (int j = 0; j < rule->accountCount; j++) {
			if (strcmp(rule->account[j], account) == 0) {
				accountMatched = 1;
				break;
			}
		}

		// IP와 계정이 모두 일치하는 경우
		if (ipMatched && accountMatched) {
			//syslog(LOG_ERR, "Match found for IP: %s and Account: %s in Rule %d", ipaddr, account, i + 1);
			return (Rule *)rule; // 일치하는 규칙의 포인터 반환
		}
	}

	//syslog(LOG_ERR, "No match found for IP: %s and Account: %s", ipaddr, account);
	return NULL; // 일치하는 규칙이 없을 경우 NULL 반환
}

int isSuPamPolicyMatched(const PamPolicy *pamPolicy, const char *ipaddr, const char *account, const char *switch_account) {
	
	bool bChkUser = false, bChkSwitchUser = false;

	for (int i = 0; i < pamPolicy->ruleCount; i++) {
		const Rule *rule = &pamPolicy->rules[i];

		// IP 주소가 규칙의 IP 리스트에 있는지 확인
		int ipMatched = 0;
		for (int j = 0; j < rule->ipCount; j++) {
		    if (strcmp(rule->ipList[j], ipaddr) == 0) {
			ipMatched = 1;
			break;
		    }
		}

		// 계정이 규칙의 계정 리스트에 있는지 확인
		int accountMatched = 0;
		for (int j = 0; j < rule->accountCount; j++) {
			if (strcmp(rule->account[j], account) == 0) {
				bChkUser = true;
			}
			
			if (strcmp(rule->account[j], switch_account) == 0)	{
				bChkSwitchUser = true;
			}
		}

		if (bChkUser == true && bChkSwitchUser == true )
		{
			accountMatched = 1;
		}


		// IP와 계정이 모두 일치하는 경우
		if (ipMatched && accountMatched) {
		    //syslog(LOG_ERR, "Match found for IP: %s and Account: %s->%s in Rule %d", ipaddr, account,switch_account, i + 1);
		    return 1;
		}
	}

	//syslog(LOG_ERR, "No match found for IP: %s and Account: %s, switch Account:%s", ipaddr, account, switch_account);
	return 0; // 일치하는 규칙이 없을 경우
}

void get_local_ip(char *ip_buffer, size_t buffer_size) {
	struct ifaddrs *ifaddr, *ifa;
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET|| strcmp(ifa->ifa_name, "lo") == 0) {
		    continue; // IPv4 주소만 처리
		}

		// 로컬 IP 주소를 가져옴
		if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), ip_buffer, buffer_size, NULL, 0, NI_NUMERICHOST) == 0) {
		    break; // 첫 번째 로컬 IP 주소를 찾음
		}
	}

	freeifaddrs(ifaddr);
}


void parse_ssh_connection(pam_handle_t *pamh, bool isConsole) 	{

	char    sDataEnv_var[MAX_ENV_STR_LEN];
	// SSH_CONNECTION 환경 변수 가져오기
	pid_t parent_pid = getppid();
	const char * sessionkey = read_env_variable(parent_pid, ENV_HIWARE_SESSIONKEY);
	const char * usernumber = read_env_variable(parent_pid, ENV_HIWARE_USER_NUMBER);
	char env_data[1024] = {0,};

	if (sessionkey)		{
		snprintf (sDataEnv_var, sizeof (sDataEnv_var), HIWARE_SESSION_KEY_FORMAT , sessionkey);
		pam_putenv(pamh, sDataEnv_var);
	}

	memset (sDataEnv_var, 0x00, sizeof (sDataEnv_var));

	if (usernumber)		{
		snprintf (sDataEnv_var, sizeof (sDataEnv_var), HIWARE_USER_NUMBER_FORMAT , usernumber);
		pam_putenv(pamh, sDataEnv_var);
	}

	if (isConsole == true )
	{
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SSH_CLIENT_IP,PAM_LOOPIPADDR);
		pam_putenv(pamh, sDataEnv_var);

		memset (sDataEnv_var, 0x00, sizeof(sDataEnv_var));

		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SSH_CLIENT_PORT,"");
		pam_putenv(pamh, sDataEnv_var);

	
		return;
	}

	const char *ssh_connection = pam_getenv(pamh,"SSH_CONNECTION");
	if (ssh_connection == NULL) {

		//pid_t parent_pid = getppid();

		ssh_connection = read_env_variable(parent_pid, "SSH_CONNECTION");

		if (ssh_connection == NULL)	{
			return;
		}
		else
		{
			char szSShconnection[256] = {0,};
			snprintf(sDataEnv_var, sizeof(sDataEnv_var), "SSH_CONNECTION=%s",ssh_connection);
			pam_putenv(pamh, sDataEnv_var);
		}
	}

	// 변수 선언
	char client_ip[16];
	char client_port[6];
	char server_ip[16];
	char server_port[6];

	// SSH_CONNECTION 문자열을 공백으로 분리하여 변수에 저장
	if (sscanf(ssh_connection, "%15s %5s %15s %5s", client_ip, client_port, server_ip, server_port) != 4) {
		return;
	}

	snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SSH_CLIENT_IP,client_ip);
    pam_putenv(pamh, sDataEnv_var);
	
	memset (sDataEnv_var, 0x00, sizeof(sDataEnv_var));

	snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SSH_CLIENT_PORT,client_port);
    pam_putenv(pamh, sDataEnv_var);

    memset (sDataEnv_var, 0x00, sizeof(sDataEnv_var));

	snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SSH_SERVER_IP,server_ip);
    pam_putenv(pamh, sDataEnv_var);

    memset (sDataEnv_var, 0x00, sizeof(sDataEnv_var));

    snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SSH_SERVER_PORT,server_port);
    pam_putenv(pamh, sDataEnv_var);

}

const char * getPamRuleFilePath(const char* sDataHomeDir)
{
	static char pam_rule_file[256];
	//snprintf (pam_rule_file, sizeof (pam_rule_file), "/%s/%s/%s/%s",sDataHomeDir, RULE_DIR, PAM_PRODUCT_NM,RULE_FILE);
	snprintf (pam_rule_file, sizeof (pam_rule_file), "/%s/%s/%s",sDataHomeDir, RULE_DIR, COMMON_RULE_FILE);
	return pam_rule_file;
}

const char * getPambakSulogFilePath(const char* sDataHomeDir)
{
	static char pam_subaklog_file[256];
        snprintf (pam_subaklog_file, sizeof (pam_subaklog_file), "/%s/%s/%s/%s/%s",sDataHomeDir, DATE_DIR, PAM_PRODUCT_NM, PAM_PRODUCT_NM,BACKUP_SULOG_FILE_WITHOUT_EXTENSION);
        return pam_subaklog_file;

}

const char * getPambakSessionlogFilePath(const char* sDataHomeDir)
{
	static char pam_sessionbaklog_file[256];
        snprintf (pam_sessionbaklog_file, sizeof (pam_sessionbaklog_file), "/%s/%s/%s/%s",sDataHomeDir, DATE_DIR,PAM_PRODUCT_NM , BACKUP_SESSION_LOG_FILE_WITHOUT_EXTENSION);
        return pam_sessionbaklog_file;
}

const char * getPambaklogFilePath(const char* sDataHomeDir)
{
	static char pam_baklog_file[256];
        snprintf (pam_baklog_file, sizeof (pam_baklog_file), "/%s/%s/%s/%s",sDataHomeDir, DATE_DIR, PAM_PRODUCT_NM, BACKUP_LOG_FILE_WITHOUT_EXTENSION);
        return pam_baklog_file;

}

const char * getPamLogFilePath(void)
{
	static char pam_log_file[256];

	const char *sDataHomeDir = getenv( ENV_HIWARE_HOME);
        if (sDataHomeDir == NULL)       {
        	sDataHomeDir  = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,   "PAM_ROOT_DIR");         // PAM_ROOT_DIR
        }

	snprintf (pam_log_file, sizeof(pam_log_file), "%s/%s/%s", sDataHomeDir, LOG_DIR, PAM_PRODUCT_NM);

	return pam_log_file;
}

const char * getPamConfFilePath(const char * sDataHomeDir)
{
	static char pam_conf_file[256];
        snprintf (pam_conf_file, sizeof (pam_conf_file), "/%s/%s/%s/%s",sDataHomeDir,CONFIG_DIR ,PAM_PRODUCT_NM , CONFIG_FILE);
        return pam_conf_file;
}

int is_valid_ip(const char *ip) 	{
	int num, dots = 0;
	char ip_copy[16]; // IPv4 주소는 최대 15자 + 널 종료 문자
	const char *ptr;

	// IP 주소가 비어있거나 너무 길면 유효하지 않음
	if (ip == NULL || strlen(ip) < 7 || strlen(ip) > 15) {
		return 0;
	}

	// 입력 문자열을 복사
    	strncpy(ip_copy, ip, sizeof(ip_copy) - 1);
    	ip_copy[sizeof(ip_copy) - 1] = '\0'; // 널 종료

	// IP 주소를 점(.)으로 분리
	ptr = strtok((char *)ip_copy, ".");
	while (ptr) {
		// 각 옥텟이 숫자로만 이루어져 있는지 확인
		if (!isdigit(*ptr)) {
		    	return 0;
		}

		// 문자열을 정수로 변환
		num = atoi(ptr);

		// 숫자가 0~255 범위에 있는지 확인
		if (num < 0 || num > 255) {
		    	return 0;
		}

		// 옥텟의 앞에 0이 있는지 확인 (예: 01, 001)
		if (ptr[0] == '0' && strlen(ptr) > 1) {
		    	return 0;
		}

		dots++;
		ptr = strtok(NULL, ".");
	}

	// 총 4개의 옥텟이 있어야 함
	return dots == 4;
}

char* get_env_var(pid_t pid, const char* var_name) {

	char path[256];
	snprintf(path, sizeof(path), "/proc/%d/environ", pid);
	FILE *file = fopen(path, "r");
	if (!file) {
		perror("fopen");
		return NULL;
	}

	char* value = NULL;
	size_t var_name_len = strlen(var_name);
	char buffer[1024];

	// 환경 변수 전체를 읽어들임
	fread(buffer, sizeof(char), sizeof(buffer), file);
	fclose(file);

	// null 문자로 구분된 환경 변수들을 확인
	char* token = strtok(buffer, "\0");
	while (token) {
	//	syslog (LOG_ERR, "get_env_var token : %s", token );
		/*if (strncmp(token, var_name, var_name_len) == 0 && token[var_name_len] == '=') {
		value = strdup(token + var_name_len + 1); // '=' 다음부터 값을 복사
		break;
	}
	token = strtok(NULL, "\0");
	*/
	}

	return value; // 호출자가 메모리를 해제해야 함
}

void print_env_vars(pid_t pid) {

	char path[256];
	snprintf(path, sizeof(path), "/proc/%d/environ", pid);
	FILE *file = fopen(path, "r");
	if (!file) {
		perror("fopen");
		return;
	}

	// 환경 변수를 저장할 버퍼
	char buffer[4096];
	size_t bytesRead = fread(buffer, sizeof(char), sizeof(buffer) - 1, file);
	fclose(file);

	// 읽은 데이터의 끝에 null 문자 추가
	buffer[bytesRead] = '\0';

	// null 문자로 구분된 환경 변수들을 한 줄씩 출력
	char* token = buffer;
	while (*token) {
		token += strlen(token) + 1; // 다음 환경 변수로 이동
	}
}

char* read_env_variable(pid_t pid, const char* var_name) {
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/environ", pid);

	FILE* file = fopen(path, "r");
	if (!file) {
		perror("fopen");
		return NULL;
	}

	char* buffer = malloc(BUFFER_SIZE);
	if (!buffer) {
		perror("malloc");
		fclose(file);
		return NULL;
	}

	size_t bytes_read = fread(buffer, 1, BUFFER_SIZE - 1, file);
	if (bytes_read == 0) {
		perror("fread");
		free(buffer);
		fclose(file);
		return NULL;
	}
	buffer[bytes_read] = '\0'; // Null-terminate the buffer

	fclose(file);

	// Parse the buffer to find the desired variable
	char* token = buffer;
	while (token < buffer + bytes_read) {
		size_t len = strlen(token);
		if (strncmp(token, var_name, strlen(var_name)) == 0 && token[strlen(var_name)] == '=') {
			//syslog (LOG_ERR, "%s", token);
		    	char* value = strdup(token + strlen(var_name) + 1);
		    	free(buffer);
		    	return value;
		}
		token += len + 1; // Move to the next null-terminated string
	}

	free(buffer);
	return NULL; // Variable not found
}

//#include <linux/tty.h>

pid_t get_tty_pid(const char* tty_name) {

	char path[64];
	snprintf(path, sizeof(path), "/dev/%s", tty_name);

	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		return -1;
	}

	int pgrp;
	if (ioctl(fd, TIOCGPGRP, &pgrp) == -1) {
		close(fd);
		return -1;
	}

	close(fd);
	return (pid_t)pgrp;
}

char* resolve_actual_tty(pid_t pid) 	{

	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/fd", pid);

	DIR* dir = opendir(path);
	if (!dir) {
		return NULL;
	}

	struct dirent* entry;
	while ((entry = readdir(dir)) != NULL) 		{
		if (entry->d_type == DT_LNK) {
			char fd_path[256], target_path[256];
			if (strlen(path) + strlen(entry->d_name) + 2 > sizeof(fd_path)) 	{
				fprintf(stderr, "[ERR] Path too long for fd_path buffer\n");
				closedir(dir);
				return NULL;
			}
			snprintf(fd_path, sizeof(fd_path), "%s/%s", path, entry->d_name);

			ssize_t len = readlink(fd_path, target_path, sizeof(target_path) - 1);
			if (len >= (ssize_t)sizeof(target_path) - 1) {
    				fprintf(stderr, "[ERR] Target path truncated\n");
    				closedir(dir);
    				return NULL;
			} else if (len != -1) 	{
				target_path[len] = '\0';
				if (strncmp(target_path, "/dev/pts/", 9) == 0) {
					closedir(dir);
					return strdup(target_path);
				}
			}
		}
	}

	closedir(dir);
	return NULL;
}

char *generate_uuid() {

	// UUID 구조체 생성
    	uuid_t uuid;
    	// UUID 문자열을 저장할 메모리 할당 (37바이트: 36자 + null 문자)
    	char *uuid_str = malloc(37);

    	if (!uuid_str) {
        	fprintf(stderr, "Memory allocation failed for UUID\n");
        	return NULL;
    	}

    	// UUID 생성
    	uuid_generate(uuid);
    	// UUID를 문자열로 변환
    	uuid_unparse(uuid, uuid_str);

    	return uuid_str;
}

int get_shell_from_pam(pam_handle_t *pamh, char **shell) 	{

	const char *username = NULL;
	struct passwd *pwd = NULL;

	// Validate input arguments
	if (!pamh || !shell) {
		return PAM_SYSTEM_ERR;
	}

	*shell = NULL; // Initialize the output pointer

	// Get the username from PAM
	int retval = pam_get_user(pamh, &username, NULL);
	if (retval != PAM_SUCCESS || !username) {
		fprintf(stderr, "Error: Failed to retrieve username from PAM.\n");
		return retval == PAM_SUCCESS ? PAM_USER_UNKNOWN : retval;
	}

	// Retrieve user information from the system
	pwd = getpwnam(username);
	if (!pwd) {
		fprintf(stderr, "Error: User '%s' not found in system.\n", username);
		return PAM_USER_UNKNOWN;
	}

	// Duplicate the shell information
	*shell = strdup(pwd->pw_shell);
	if (!*shell) {
		fprintf(stderr, "Error: Memory allocation for shell string failed.\n");
		return PAM_BUF_ERR;
	}

	return PAM_SUCCESS;
}

bool is_pam_user_ndshell(pam_handle_t *pamh) 	{

	const char *username = NULL;
	struct passwd *pwd = NULL;

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
        if (sDataHomeDir == NULL)	{
		sDataHomeDir = getenv (ENV_HIWARE_HOME);
		if (sDataHomeDir == NULL )
			sDataHomeDir  = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,   "PAM_ROOT_DIR");         // PAM_ROOT_DIR
	}

	//char *ndshell_path = "/hiagt/bin/ndshell";
	char ndshell_path[256] = {0,};
	char *user_shell = NULL;

	// Validate the input argument
	if (!pamh) {
		return false;
	}

	snprintf(ndshell_path, sizeof(ndshell_path),"%s/bin/ndshell", sDataHomeDir);

	// Get the username from PAM
	int retval = pam_get_user(pamh, &username, NULL);
	if (retval != PAM_SUCCESS || !username) {
		return false;
	}

	// Retrieve user information from the system
	pwd = getpwnam(username);
	if (!pwd) {
		return false;
	}

	// Get the user's shell
	user_shell = pwd->pw_shell;

	// Check if the shell matches "/hiagt/bin/ndshell"
	if (user_shell && strcmp(user_shell, ndshell_path) == 0) {

		return true;
	}

	return false;
}

int get_agent_id(const char *filename) {

	FILE *file = fopen(filename, "r");
	if (!file) {
		perror("[ERR] Failed to open JSON file");
		return NULL;
	}

	// Get file size
	struct stat file_stat;
	if (stat(filename, &file_stat) != 0) {
		perror("[ERR] Failed to get file size");
		fclose(file);
		return NULL;
	}

	// Allocate memory for the file content
	char *json_content = (char *)malloc(file_stat.st_size + 1);
	if (!json_content) {
		perror("[ERR] Failed to allocate memory for JSON content");
		fclose(file);
		return NULL;
	}

	// Read file content into the buffer
	fread(json_content, 1, file_stat.st_size, file);
	json_content[file_stat.st_size] = '\0'; // Null-terminate the string

	fclose(file);
	return json_content;
}

// Function to get the value of a given key as a string
const char *get_value_as_string(const char *json_file, const char *key) {

	FILE *file = fopen(json_file, "r");
	if (!file) {
		return NULL;
	}

	fseek(file, 0, SEEK_END);
	size_t length = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *json_data = calloc(length + 1, sizeof(char));
	if (!json_data) {
		fclose(file);
		return NULL;
	}

	fread(json_data, 1, length, file);
	fclose(file);

	struct json_object *parsed_json = json_tokener_parse(json_data);
	free(json_data);

	if (!parsed_json) {
		return NULL;
	}

	struct json_object *value;
	if (!json_object_object_get_ex(parsed_json, key, &value)) {
		json_object_put(parsed_json);
		return NULL;
	}

	const char *value_str;
	if (json_object_is_type(value, json_type_string)) {
		value_str = json_object_get_string(value);
	} else if (json_object_is_type(value, json_type_int)) {
		static char buffer[32];
		snprintf(buffer, sizeof(buffer), "%d", json_object_get_int(value));
		value_str = buffer;
	} else {
		json_object_put(parsed_json);
		return NULL;
	}

	json_object_put(parsed_json);
	return strdup(value_str);
}

int check_pam_policy(const char *json_file, const char *ip, const char *account, int *pri_no, char **agt_auth_no, int *action, int *logging) 	{

	FILE *file = fopen(json_file, "r");
	if (!file) 	{
		return 0;
	}

	if (ip == NULL || account == NULL)
	{
		fclose(file);
		return 0;
	}

	fseek(file, 0, SEEK_END);
	size_t length = ftell(file);
	fseek(file, 0, SEEK_SET);

	if (length > 1024 * 1024) { // Limit file size to 1MB
		fclose(file);
		return 0;
    	}

	char *json_data = malloc(length + 1);
	fread(json_data, 1, length, file);
	fclose(file);
	json_data[length] = '\0';

	struct json_object *parsed_json = json_tokener_parse(json_data);
	free(json_data);

	if (!parsed_json) 	{

		nd_log (NDLOG_ERR, "failed to parsed json...");
		return 0;
	}

	nd_log (NDLOG_TRC, "json_file : %s", json_file);
	
	nd_log (NDLOG_TRC, "Parsed JSON:\n%s\n", json_object_to_json_string_ext(parsed_json, JSON_C_TO_STRING_PRETTY));

	struct json_object *pam_policy, *rule_list, *rule, *ip_list, *account_list;
	if (!json_object_object_get_ex(parsed_json, "pamPolicy", &pam_policy) ||
	    !json_object_object_get_ex(pam_policy, "ruleList", &rule_list)) 	{
		json_object_put(parsed_json);
		return 0;
	}

#ifdef _OLD_SRC_
	for (int i = 0; i < json_object_array_length(rule_list); i++) 	{
		rule = json_object_array_get_idx(rule_list, i);

		if (json_object_object_get_ex(rule, "ipList", &ip_list) &&
		    json_object_object_get_ex(rule, "account", &account_list)) 		{

		    	// Check for matching IP
		    	for (int j = 0; j < json_object_array_length(ip_list); j++) 		{
				const char *rule_ip = json_object_get_string(json_object_array_get_idx(ip_list, j));
				if (strcmp(rule_ip, ip) == 0) {
				    	// Check for matching account
				    	for (int k = 0; k < json_object_array_length(account_list); k++) 	{
						const char *rule_account = json_object_get_string(json_object_array_get_idx(account_list, k));
						if (strcmp(rule_account, account) == 0) 	{
						    	*pri_no = json_object_get_int(json_object_object_get(rule, "priNo"));
						    	*agt_auth_no = strdup(json_object_get_string(json_object_object_get(rule, "agtAuthNo")));
						    	*action = json_object_get_int(json_object_object_get(rule, "action"));
						    	*logging = json_object_get_int(json_object_object_get(rule, "logging"));
						    	json_object_put(parsed_json);
						    	return 1;
						}
				    	}
				}
		    	}
		}
	}
#endif //_OLD_SRC_

	// Iterate through rules
	for (int i = 0; i < json_object_array_length(rule_list); i++) {
		struct json_object *rule = json_object_array_get_idx(rule_list, i);
		struct json_object *ip_list, *account_list;

		if (json_object_object_get_ex(rule, "ipList", &ip_list) &&
		    json_object_object_get_ex(rule, "acctIdList", &account_list)) {

		   	 // Check IP match
		    	for (int j = 0; j < json_object_array_length(ip_list); j++) {
				const char *rule_ip = json_object_get_string(json_object_array_get_idx(ip_list, j));

				if (is_ip_in_range(rule_ip, ip)) { // IP 범위 처리
			    	// Check account match
					for (int k = 0; k < json_object_array_length(account_list); k++) {
						const char *rule_account = json_object_get_string(json_object_array_get_idx(account_list, k));
							if (strcmp(rule_account, account) == 0) {
							*pri_no = json_object_get_int(json_object_object_get(rule, "priNo"));
							*agt_auth_no = strdup(json_object_get_string(json_object_object_get(rule, "agtAuthNo")));
							*action = json_object_get_int(json_object_object_get(rule, "pmsShutYn")); // old "action"
							*logging = json_object_get_int(json_object_object_get(rule, "logUseYn"));  // old "logging"
							json_object_put(parsed_json);
							return 1;
						}
			    		}
				}
		    	}
		}
	}

	json_object_put(parsed_json);
	return 0;
}


#ifdef _OLD_SRC_
int check_pam_policy(const char *json_file, const char *ip, const char *account, int *pri_no, char **agt_auth_no) 	{

	FILE *file = fopen(json_file, "r");
	if (!file) {
		perror("[ERR] Failed to open JSON file");
		return 0;
	}

	fseek(file, 0, SEEK_END);
	size_t length = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *json_data = malloc(length + 1);
	fread(json_data, 1, length, file);
	fclose(file);
	json_data[length] = '\0';

	struct json_object *parsed_json = json_tokener_parse(json_data);
	free(json_data);

	if (!parsed_json) {
		fprintf(stderr, "[ERR] Failed to parse JSON data.\n");
		return 0;
	}

	struct json_object *pam_policy, *rule_list, *rule, *ip_list, *account_list;
	if (!json_object_object_get_ex(parsed_json, "pamPolicy", &pam_policy) ||
		!json_object_object_get_ex(pam_policy, "ruleList", &rule_list)) {
		fprintf(stderr, "[ERR] pamPolicy.ruleList not found.\n");
		json_object_put(parsed_json);
		return 0;
	}

	for (int i = 0; i < json_object_array_length(rule_list); i++) {
		rule = json_object_array_get_idx(rule_list, i);

		if (json_object_object_get_ex(rule, "ipList", &ip_list) &&
		    	json_object_object_get_ex(rule, "account", &account_list)) {

			/*
		    		// Check for matching IP
			*/
		    	for (int j = 0; j < json_object_array_length(ip_list); j++) {
				const char *rule_ip = json_object_get_string(json_object_array_get_idx(ip_list, j));
				if (strcmp(rule_ip, ip) == 0) {
					/*
				    		// Check for matching account
					*/
				    	for (int k = 0; k < json_object_array_length(account_list); k++) {
						const char *rule_account = json_object_get_string(json_object_array_get_idx(account_list, k));
						if (strcmp(rule_account, account) == 0) {
							*pri_no = json_object_get_int(json_object_object_get(rule, "priNo"));
							*agt_auth_no = strdup(json_object_get_string(json_object_object_get(rule, "agtAuthNo")));
							json_object_put(parsed_json);
							return 1;
						}
				    	}
				}
			}
		}
	}

	json_object_put(parsed_json);
	return 0;
}

#endif

int check_sam_policy(const char *json_file, const char *ip, const char *account, int *pri_no, char **agt_auth_no) 	{

	FILE *file = fopen(json_file, "r");
	if (!file) {
		perror("[ERR] Failed to open JSON file");
		return 0;
	}

	fseek(file, 0, SEEK_END);
	size_t length = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *json_data = malloc(length + 1);
	fread(json_data, 1, length, file);
	fclose(file);
	json_data[length] = '\0';

	struct json_object *parsed_json = json_tokener_parse(json_data);
	free(json_data);

	if (!parsed_json) {
		fprintf(stderr, "[ERR] Failed to parse JSON data.\n");
		return 0;
	}

	struct json_object *sam_policy, *rule_list, *rule, *ip_list, *account_list;
	if (!json_object_object_get_ex(parsed_json, "samPolicy", &sam_policy) ||
	    !json_object_object_get_ex(sam_policy, "ruleList", &rule_list)) 	{
		fprintf(stderr, "[ERR] samPolicy.ruleList not found.\n");
		json_object_put(parsed_json);
		return 0;
	}

	for (int i = 0; i < json_object_array_length(rule_list); i++) 		{
		rule = json_object_array_get_idx(rule_list, i);

		if (json_object_object_get_ex(rule, "ipList", &ip_list) &&
		    json_object_object_get_ex(rule, "acctIdList", &account_list)) 		{

		    // Check for matching IP
		    for (int j = 0; j < json_object_array_length(ip_list); j++) 	{
				const char *rule_ip = json_object_get_string(json_object_array_get_idx(ip_list, j));
				if (strcmp(rule_ip, ip) == 0) 		{
					// Check for matching account
					for (int k = 0; k < json_object_array_length(account_list); k++) 		{
						const char *rule_account = json_object_get_string(json_object_array_get_idx(account_list, k));
						if (strcmp(rule_account, account) == 0) 	{
							*pri_no = json_object_get_int(json_object_object_get(rule, "priNo"));
							*agt_auth_no = strdup(json_object_get_string(json_object_object_get(rule, "agtAuthNo")));
							json_object_put(parsed_json);
							return 1;
						}
					}
				}
			}
		}
	}

	json_object_put(parsed_json);
	return 0;
}

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
	    const char *sys_account,
	    const char *hiware_account,
	    const char *switch_sys_account,
	    const char *message,
	    const char *result,
	    const char *certTpCode,
	    const char *certAppTpCode,
	    const char *certSucesFailYn,
	    const char *certStepSeqNo
) {

	struct _archive_log *log = malloc(sizeof(struct _archive_log));
	if (!log) {
		fprintf(stderr, "[ERR] Failed to allocate memory for archive log\n");
		return NULL;
	}

	// Safely populate the struct with input values or empty strings
	snprintf(log->prefix, 		ND_PREFIX_MAX_LEN, 		"%s", 	prefix 		? prefix : "");
	snprintf(log->agentId, 		ND_AGENTID_MAX_LEN, 		"%s", 	agentId 	? agentId : "");
	snprintf(log->agtAuthNo, 	ND_AGTAUTHNO_MAX_LEN, 		"%s", 	agtAuthNo 	? agtAuthNo : "");
	snprintf(log->pamAgtAuthNo,        ND_AGTAUTHNO_MAX_LEN,           "%s",   agtAuthNo       ? agtAuthNo : "");
	snprintf(log->sessionKey, 	ND_UUID_LENGTH, 		"%s", 	sessionKey 	? sessionKey : "");
	snprintf(log->time, 		ND_TIME_MAX_LEN, 		"%s", 	time 		? time : "");
	snprintf(log->connect_type, 	ND_CONNECTTYPE_MAX_LEN, 	"%s", 	connect_type 	? connect_type : "");
	snprintf(log->sourceIp,	 	ND_SOURCEIP_MAX_LEN, 		"%s", 	sourceIp 	? sourceIp : "");
	snprintf(log->last_auth_type, 	ND_LASTAUTHTYPE_MAX_LEN, 	"%s", 	last_auth_type 	? last_auth_type : "");
	snprintf(log->secur_step_no, 	ND_SECUR_STEP_NO_MAX_LEN, 	"%s", 	PAM_SECUR_STEP_PAM);
	snprintf(log->sys_account, 	ND_SYSACCOUNT_MAX_LEN, 		"%s", 	sys_account 	? sys_account : "");
	snprintf(log->hiware_account, 	ND_HIWAREACCOUNT_MAX_LEN, 	"%s", 	hiware_account 	? hiware_account : "");
	snprintf(log->switch_sys_account, ND_SWITCHUSER_MAX_LEN, 	"%s", 	switch_sys_account ? switch_sys_account : "");
	snprintf(log->message, 		ND_LOGMSG_MAX_LEN, 		"%s", 	message 	? message : "");
	snprintf(log->result, 		ND_LOGRESULT_MAX_LEN, 		"%s", 	result 		? result : "");

	snprintf(log->certTpCode,       ND_CERT_TP_CODE_MAX_LEN,         "%s",   certTpCode          ? certTpCode : "");
	snprintf(log->certAppTpCode,    ND_CERT_APP_TP_CODE_MAX_LEN,     "%s",   certAppTpCode       ? certAppTpCode : "");
	snprintf(log->certSucesFailYn,  ND_CERT_APP_SUCES_FAIL_YN_MAX_LEN,  "%s",  certSucesFailYn   ? certSucesFailYn : "");
	snprintf(log->certStepSeqNo,    ND_CERT_STEP_SEQ_NO_MAX_LEN,     "%s",   certStepSeqNo       ? certStepSeqNo : "");

	return log;
}
#else //_OLD_SRC
struct _archive_log* create_archive_log(
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
) 
{
	struct _archive_log *log = malloc(sizeof(struct _archive_log));
        if (!log) {
                fprintf(stderr, "[ERR] Failed to allocate memory for archive log\n");
                return NULL;
        }

	snprintf(log->svrConnStartTime,		ND_TIME_MAX_LEN,			svrConnStartTime	?svrConnStartTime 	: "");
        snprintf(log->svrConnEndTime,		ND_TIME_MAX_LEN,			svrConnEndTime		?svrConnEndTime 	: "");
        snprintf(log->svrConnRstTpCode,		4,					svrConnRstTpCode	?svrConnRstTpCode 	: "");
        snprintf(log->svrConnFailRsnCode,	4,					svrConnFailRsnCode	?svrConnFailRsnCode 	: "");
        snprintf(log->agtNo,			16,					agtNo			?agtNo 			: "");
        snprintf(log->agtConnFormTpCode,	4,					agtConnFormTpCode	?agtConnFormTpCode 	: "");
        snprintf(log->agtAuthNo,		ND_AGTAUTHNO_MAX_LEN,			agtAuthNo		?agtAuthNo 		: "");
        snprintf(log->portNo,			8,					portNo			?portNo 		: "");
        snprintf(log->userIp,			ND_SOURCEIP_MAX_LEN,			userIp			?userIp 		: "");
        snprintf(log->securStepNo,		ND_SECUR_STEP_NO_MAX_LEN,		securStepNo		?securStepNo 		: "");
        snprintf(log->svrConnSessKey,		ND_UUID_LENGTH,				svrConnSessKey		?svrConnSessKey 	: "");
        snprintf(log->connAcctId,		ND_SYSACCOUNT_MAX_LEN,			connAcctId		?connAcctId 		: "");
	snprintf(log->switchAcctId,		ND_SYSACCOUNT_MAX_LEN,			switchAcctId		?switchAcctId		: "");
        snprintf(log->pamAgtAuthNo,		ND_AGTAUTHNO_MAX_LEN,			pamAgtAuthNo		?pamAgtAuthNo 		: "");
        snprintf(log->userNo,			18,					userNo			?userNo 		: "");
        snprintf(log->pamCertDtlCode,		4,					pamCertDtlCode		?pamCertDtlCode 	: "");
	snprintf(log->pamCertDtlAuthCode,	4, 					pamCertDtlAuthCode	?pamCertDtlAuthCode	: "");

        snprintf(log->certTpCode,		ND_CERT_TP_CODE_MAX_LEN,		certTpCode		?certTpCode 		: "");
        snprintf(log->certAppTpCode,		ND_CERT_APP_TP_CODE_MAX_LEN,		certAppTpCode		?certAppTpCode 		: "");
        snprintf(log->certSucesFailYn,		ND_CERT_APP_SUCES_FAIL_YN_MAX_LEN,	certSucesFailYn		?certSucesFailYn 	: "");
        snprintf(log->certStepSeqNo,		ND_CERT_STEP_SEQ_NO_MAX_LEN,		certStepSeqNo		?certStepSeqNo 		: "");



	return log;
}

#endif //_OLD_SRC

void free_archive_log(struct _archive_log *log) {

	if (log != NULL) {
		free(log);
		log = NULL;
	}
}

/*
	//
*/
int is_ip_in_range(const char *ip, const char *range) {
	struct in_addr ip_addr, start_addr, end_addr;

	// Check if the range is an IP range
	char start[16], end[16];
	if (sscanf(range, "%15[^-]-%15s", start, end) == 2) {
		if (inet_aton(ip, &ip_addr) == 0 || inet_aton(start, &start_addr) == 0 || inet_aton(end, &end_addr) == 0) {
		    	return 0; // Invalid IP format
		}
		return ntohl(ip_addr.s_addr) >= ntohl(start_addr.s_addr) && ntohl(ip_addr.s_addr) <= ntohl(end_addr.s_addr);
	}

	// Check if the range is a single IP
	if (inet_aton(ip, &ip_addr) == 0 || inet_aton(range, &start_addr) == 0) {
		return 0; // Invalid IP format
	}

	return ntohl(ip_addr.s_addr) == ntohl(start_addr.s_addr);
}

/*
	//
*/
int is_account_in_list(const char *account, struct json_object *account_list) {
	int array_len = json_object_array_length(account_list);
	for (int i = 0; i < array_len; i++) {
		const char *json_account = json_object_get_string(json_object_array_get_idx(account_list, i));
		if (strcmp(account, json_account) == 0) {
		    	return 1;
		}
	}
	return 0;
}

/*
	//
*/
int is_time_in_range(const char *start, const char *end, time_t current_time) {


	struct tm tm_start = {0}, tm_end = {0};
	time_t time_start, time_end;

	// Parse start time
	if (!strptime(start, "%Y.%m.%d %H:%M", &tm_start)) {
		return 0;
	}

	// Parse end time
	if (!strptime(end, "%Y.%m.%d %H:%M", &tm_end)) {
		return 0;
	}

	// Convert to time_t
	time_start = mktime(&tm_start);
	time_end = mktime(&tm_end);

	// Validate range
	if (time_start == -1 || time_end == -1) {
		return 0;
	}

	if (time_start > time_end) {
		return 0;
	}

	// Compare with current_time
	return current_time >= time_start && current_time <= time_end;
}

/*
	//
*/
int is_wday_time_valid(const struct json_object *wday_list, int current_wday, time_t current_time) 	{

	int array_len = json_object_array_length(wday_list);
	struct tm *tm_current = localtime(&current_time);

	for (int i = 0; i < array_len; i++) {
		struct json_object *wday_obj = json_object_array_get_idx(wday_list, i);
		int wday = json_object_get_int(json_object_object_get(wday_obj, "wday"));

		if (wday == current_wday) {
			const char *start = json_object_get_string(json_object_object_get(wday_obj, "start"));
			const char *end = json_object_get_string(json_object_object_get(wday_obj, "end"));

			struct tm tm_start = {0}, tm_end = {0};
			time_t time_start, time_end;

			if (!strptime(start, "%H:%M", &tm_start) || !strptime(end, "%H:%M", &tm_end)) {
				fprintf(stderr, "Invalid start or end time format\n");
				continue;
			}

			// Ensure the year, month, and day match the current time
			tm_start.tm_year = tm_current->tm_year;
			tm_start.tm_mon = tm_current->tm_mon;
			tm_start.tm_mday = tm_current->tm_mday;

			tm_end.tm_year = tm_current->tm_year;
			tm_end.tm_mon = tm_current->tm_mon;
			tm_end.tm_mday = tm_current->tm_mday;

			time_start = mktime(&tm_start);
			time_end = mktime(&tm_end);

			if (time_start == -1 || time_end == -1) {
				fprintf(stderr, "Error converting time\n");
				continue;
			}

			// Handle cases where end time is before start time (e.g., overnight ranges)
			if (time_end < time_start) {
				time_end += 24 * 3600; // Add 24 hours to end time
			}

			// Adjust current time to UTC if necessary
			time_t adjusted_current_time = current_time;
			if (tm_current->tm_isdst > 0) {
				adjusted_current_time -= timezone;
			}

			if (adjusted_current_time >= time_start && adjusted_current_time <= time_end) {
				return 1;
			}
		}
	}
	return 0;
}

/*
	//
*/
int validate_json_sampolicy(const char *json_file, const char *ip, const char *account, time_t current_time, int current_wday) {

	FILE *file = fopen(json_file, "r");
	if (!file) {
		return 0;
	}

	fseek(file, 0, SEEK_END);
	size_t length = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *data = malloc(length + 1);
	fread(data, 1, length, file);
	fclose(file);
	data[length] = '\0';

	struct json_object *parsed_json = json_tokener_parse(data);
	free(data);
	if (!parsed_json) {
		return 0;
	}

	struct json_object *sam_policy;
	if (!json_object_object_get_ex(parsed_json, "samPolicy", &sam_policy)) {
		json_object_put(parsed_json);
		return 0;
	}

	struct json_object *rule_list = json_object_object_get(sam_policy, "ruleList");
	int rule_len = json_object_array_length(rule_list);

	for (int i = 0; i < rule_len; i++) {
		struct json_object *rule = json_object_array_get_idx(rule_list, i);
		struct json_object *ip_list = json_object_object_get(rule, "ipList");
		struct json_object *account_list = json_object_object_get(rule, "account");
		struct json_object *access_date = json_object_object_get(rule, "accessDate");
		struct json_object *wday_list = json_object_object_get(rule, "wdayList");

		int ip_match = 0;
		int ip_len = json_object_array_length(ip_list);
		for (int j = 0; j < ip_len; j++) {
		    	const char *range = json_object_get_string(json_object_array_get_idx(ip_list, j));

		    	if (is_ip_in_range(ip, range)) {
				ip_match = 1;
				break;
		    	}
		}

		if (ip_match == 0) continue;


		if (!is_account_in_list(account, account_list)) continue;

		const char *start_date = json_object_get_string(json_object_object_get(access_date, "start"));
		const char *end_date = json_object_get_string(json_object_object_get(access_date, "end"));

		if (!is_time_in_range(start_date, end_date, current_time)) continue;

		if (!is_wday_time_valid(wday_list, current_wday, current_time)) continue;

		//*agt_auth_no = strdup(json_object_get_string(json_object_object_get(rule, "agtAuthNo")));
		
		json_object_put(parsed_json);
		return 1;
	}

	json_object_put(parsed_json);
	return 0;
}


/*
        //
*/
int validate_json_sampolicy_without_date(const char *json_file, const char *ip, const char *account, char **agtAuthNo,int *action, int *logging ) {

        FILE *file = fopen(json_file, "r");
        if (!file) {
                return 0;
        }

	int retval = 0;

        fseek(file, 0, SEEK_END);
        size_t length = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *data = malloc(length + 1);
        fread(data, 1, length, file);
        fclose(file);
        data[length] = '\0';

        struct json_object *parsed_json = json_tokener_parse(data);
        free(data);
        if (!parsed_json) {
                return 0;
        }

        struct json_object *sam_policy;
        if (!json_object_object_get_ex(parsed_json, "samPolicy", &sam_policy)) {
                json_object_put(parsed_json);
                return 0;
        }

        struct json_object *rule_list = json_object_object_get(sam_policy, "ruleList");
        int rule_len = json_object_array_length(rule_list);

        for (int i = 0; i < rule_len; i++) {
                struct json_object *rule = json_object_array_get_idx(rule_list, i);
                struct json_object *ip_list = json_object_object_get(rule, "ipList");
                struct json_object *account_list = json_object_object_get(rule, "account");
/*
                struct json_object *access_date = json_object_object_get(rule, "accessDate");
                struct json_object *wday_list = json_object_object_get(rule, "wdayList");
*/
                int ip_match = 0;
                int ip_len = json_object_array_length(ip_list);
                for (int j = 0; j < ip_len; j++) {
                        const char *range = json_object_get_string(json_object_array_get_idx(ip_list, j));

                        if (is_ip_in_range(ip, range)) {
                                ip_match = 1;
                                break;
                        }
                }

                if (ip_match == 0) continue;

                if (!is_account_in_list(account, account_list)) continue;

		*agtAuthNo = strdup(json_object_get_string(json_object_object_get(rule, "agtAuthNo")));
		//int action = json_object_get_int(json_object_object_get(rule, "action"));
		*action = json_object_get_int(json_object_object_get(rule, "action"));
                *logging = json_object_get_int(json_object_object_get(rule, "logging"));

/*
                const char *start_date = json_object_get_string(json_object_object_get(access_date, "start"));
                const char *end_date = json_object_get_string(json_object_object_get(access_date, "end"));

                if (!is_time_in_range(start_date, end_date, current_time)) continue;

                if (!is_wday_time_valid(wday_list, current_wday, current_time)) continue;

*/
                json_object_put(parsed_json);
                return 1;
        }

        json_object_put(parsed_json);
        return 0;
}



/*
        //
*/
int validate_json_exceptionConnection(const char *json_file, const char *ip ) {

	FILE *file = fopen(json_file, "r");
        if (!file) {
                return 0;
        }

        int retval = 0;
	struct json_object *parsed_json, *exceptionIpList, *ip_obj;
    	int array_len, i;

        fseek(file, 0, SEEK_END);
        size_t length = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *data = malloc(length + 1);
        fread(data, 1, length, file);
        fclose(file);
        data[length] = '\0';

        parsed_json = json_tokener_parse(data);
        free(data);
        if (!parsed_json) {
                return 0;
        }

	// exceptionIpList 키 확인
	if (!json_object_object_get_ex(parsed_json, "exceptionIpList", &exceptionIpList)) {
		fprintf(stderr, "Key 'exceptionIpList' not found\n");
		json_object_put(parsed_json); // 메모리 해제
		return 0;
	}

	// 배열인지 확인
	if (json_object_get_type(exceptionIpList) != json_type_array) {
		fprintf(stderr, "'exceptionIpList' is not an array\n");
		json_object_put(parsed_json); // 메모리 해제
		return 0;
	}

	// 배열 길이 가져오기
	array_len = json_object_array_length(exceptionIpList);
	for (i = 0; i < array_len; i++) {
		// 배열의 각 요소 가져오기
		ip_obj = json_object_array_get_idx(exceptionIpList, i);
		const char *list_ip = json_object_get_string(ip_obj);

		// 입력된 IP와 비교
		if (strcmp(list_ip, ip) == 0) {
		    	json_object_put(parsed_json); // 메모리 해제
		   	return 1; // IP가 리스트에 있음
		}
	}

	// 메모리 해제
	json_object_put(parsed_json);
	return 0; // IP가 리스트에 없음

}


int check_su_session(pam_handle_t *pamh) 	{

	const char *current_user = NULL;
	const char *ruser = NULL;

	// Retrieve the target user (current_user)
	if (pam_get_user(pamh, &current_user, NULL) != PAM_SUCCESS || current_user == NULL) {
		return -1;
	}

	// Retrieve the original user (RUSER)
	if (pam_get_item(pamh, PAM_RUSER, (const void **)&ruser) != PAM_SUCCESS || ruser == NULL) {
		return -1;
	}

	// If the original user and target user are the same, it's not a valid SU session
	if (strcmp(ruser, current_user) == 0) {
		//syslog(LOG_WARNING, "SU session rejected: Target user is the same as original user");
		return -1;
	}

	return 0; // Valid SU session
}

// Function to initialize session info
SessionInfo *init_session_info() {
        SessionInfo *info = (SessionInfo *)malloc(sizeof(SessionInfo));
        if (!info) return NULL;

        info->current_user = NULL;
        info->target_user = NULL;
        info->remote_host = NULL;
        info->tty = NULL;
        info->type = 0;

        return info;
}

// Function to free session info
void free_session_info(SessionInfo *info) {
        if (info) {
                free(info->current_user);
                free(info->target_user);
                free(info->remote_host);
                free(info->tty);
                free(info);
        }
}

// Utility function to retrieve PAM items
char *get_pam_item_str(pam_handle_t *pamh, int item_type) {
        const void *item;
        if (pam_get_item(pamh, item_type, &item) == PAM_SUCCESS && item) {
                return strdup((const char *)item);
        }
        return strdup("unknown"); // Default value
}

// Function to collect console session info
SessionInfo *get_console_session_info(pam_handle_t *pamh) {
        SessionInfo *info = init_session_info();
        if (!info) return NULL;

        info->current_user = get_pam_item_str(pamh, PAM_USER);
        info->target_user = get_pam_item_str(pamh, PAM_RUSER);
        info->tty = get_pam_item_str(pamh, PAM_TTY);
        info->remote_host = strdup("127.0.0.1"); // Set to loopback IP
        info->type = 1;

        return info;
}

// Function to collect SSH session info
SessionInfo *get_ssh_session_info(pam_handle_t *pamh) {
        SessionInfo *info = init_session_info();
        if (!info) return NULL;

        info->current_user = get_pam_item_str(pamh, PAM_USER);
        info->target_user = get_pam_item_str(pamh, PAM_RUSER);
        info->tty = get_pam_item_str(pamh, PAM_TTY);
        info->remote_host = get_pam_item_str(pamh, PAM_RHOST);
        info->type = 2;

        return info;
}

// Function to collect su session info
SessionInfo *get_su_session_info(pam_handle_t *pamh) {

	SessionInfo *info = init_session_info();
        if (!info) return NULL;

        info->current_user = get_pam_item_str(pamh, PAM_USER);
        info->target_user = get_pam_item_str(pamh, PAM_RUSER);
        info->tty = get_pam_item_str(pamh, PAM_TTY);

        // Attempt to retrieve remote_host, fallback to default if failed
        const void *item;
        if (pam_get_item(pamh, PAM_RHOST, &item) == PAM_SUCCESS && item) {
                info->remote_host = strdup((const char *)item);
        } else {
                // Fallback logic to determine remote_host using environment variables
                const char *env_host = getenv("SSH_CLIENT");
                if (env_host) {
                        // Extract IP address from SSH_CLIENT environment variable
                        char *host_copy = strdup(env_host);
                        char *space = strchr(host_copy, ' ');
                        if (space) *space = '\0';
                        info->remote_host = host_copy;
                } else {
                        info->remote_host = strdup("localhost");
                }
        }

        info->type = 3;

        return info;

}


int get_ssh_listening_port() {
        // Try to get the port from SSH_CONNECTION environment variable
        const char *ssh_env = getenv("SSH_CONNECTION");
        if (ssh_env) {
                int local_port;
                if (sscanf(ssh_env, "%*s %*s %*s %d", &local_port) == 1) {
                        return local_port;
                }
        }

        // Fallback to using a system command (ss)
        FILE *fp = popen("ss -tnlp | grep sshd", "r");
        if (!fp) {
                perror("popen failed");
                return -1;
        }

        char line[256];
        int port = -1;

        while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "%*s %*s %*s *:%d", &port) == 1) {
                        break;
                }
        }

        pclose(fp);
        return (port > 0) ? port : 22; // Default to 22
}

// Function to parse sshd_config and find the Port directive
int get_ssh_port_from_config(const char *config_path) {
        FILE *fp = fopen(config_path, "r");
        if (!fp) {
                perror("Failed to open sshd_config");
                return -1;
        }

        char line[256];
        while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "Port", 4) == 0) {
                        int port;
                        if (sscanf(line, "Port %d", &port) == 1) {
                                fclose(fp);
                                return port;
                        }
                }
        }

        fclose(fp);
        return -1; // Port not found
}

int _get_ssh_port() {
        // First, try to read from /proc/net/tcp
        int port = get_ssh_listening_port();
        if (port != -1) {
                return port;
        }

        // If not found, fallback to sshd_config
        return get_ssh_port_from_config("/etc/ssh/sshd_config");
}

int get_ssh_listening_port_from_cmd() {
    FILE *fp = popen("ss -tnlp | grep sshd", "r");
    if (!fp) {
        perror("popen failed");
        return -1;
    }

    char line[256];
    int port = -1;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "LISTEN %*s *:%d", &port) == 1) {
            break;
        }
    }

    pclose(fp);
    return (port > 0) ? port : 22; // Default to 22
}

int get_current_ssh_port(pam_handle_t *pamh) {
        const char *ssh_env = getenv("SSH_CONNECTION");
        if (!ssh_env) {
                //syslog(LOG_ERR, "SSH_CONNECTION environment variable is not set");
                return -1;
        }

        int remote_port;
        char client_ip[128];
        if (sscanf(ssh_env, "%127s %*d %*s %d", client_ip, &remote_port) == 2) {
                //syslog(LOG_INFO, "SSH connection from %s, remote port: %d", client_ip, remote_port);
                return remote_port;
        }

        return -1;
}

int _get_current_ssh_port(pam_handle_t *pamh) {
        const void *item;
        int socket_fd;
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);

        // Get the file descriptor for the current SSH session
        if (pam_get_item(pamh, PAM_TTY, &item) != PAM_SUCCESS || !item) {
                return -1;
        }

        // Try to get the socket descriptor (mocked for demonstration)
        socket_fd = 0; // Replace with the actual SSH socket file descriptor

        if (getsockname(socket_fd, (struct sockaddr *)&addr, &addr_len) == -1) {
                return -1;
        }

        // Check if the socket is IPv4 and return the port
        if (addr.sin_family == AF_INET) {
                return ntohs(addr.sin_port);
        }

        return -1;
}

int get_ssh_port_from_command() {
        FILE *fp = popen("ss -tnlp | grep sshd", "r");
        if (!fp) {
                return -1;
        }

        char line[256];
        int port = -1;
        while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "%*s %*s %*s %*s *:%d", &port) == 1) {
                        break;
                }
        }

        pclose(fp);
        return port > 0 ? port : -1;
}

int get_ssh_port(pam_handle_t *pamh) {
        int port = get_current_ssh_port(pamh); // Use environment variable
        if (port < 0) {
                port = get_ssh_port_from_command(); // Fallback to command-based approach
        }

        if (port > 0) {
                return port;
        }

        return -1;
}

// Implementation of the function to read configuration values
char* read_config_value(const char* filename, const char* section, const char* key) {
	FILE* file = fopen(filename, "r");
	if (!file) {
		perror("Unable to open configuration file");
		return NULL;
	}

	char line[MAX_LINE_LENGTH];
	int in_section = 0;
	size_t key_len = strlen(key);

	while (fgets(line, sizeof(line), file)) {
		// Remove whitespace and newline characters
		line[strcspn(line, "\r\n")] = 0;

		// Find the section
		if (line[0] == '[') {
		    	in_section = strncmp(line + 1, section, strlen(section)) == 0 && line[strlen(section) + 1] == ']';
		    	continue;
		}

		// Find the key value within the section
		if (in_section && strncmp(line, key, key_len) == 0 && line[key_len] == '=') {
		    	fclose(file);
		    	char* value = strdup(line + key_len + 1);
		    	return value; // Return the found value
		}
	}

	fclose(file);
	return NULL; // Return NULL if no value is found
}

// Function to get environment variable (PAM or global)
const char* get_env_variable(pam_handle_t *pamh, const char *key) 	{

	// Try to get value from PAM environment
	const char* value = pam_getenv(pamh, key);
	if (value) {
		return value; // Return PAM environment value if found
	}

	// If not found in PAM, check global environment
	value = getenv(key);
	return value; // Return global environment value or NULL if not found
}
