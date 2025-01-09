#include <stdio.h>
#include <stdlib.h>
#include "nd_nix_logs.h"
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <sys/file.h> 
#include "../common.h"

#define MAX_RETRY_COUNT 3

void nd_pam_archive_log (struct _msg_header_ header, struct _archive_log logitem ,char * product_nm )
{
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	struct timeval tv;
	struct tm *tm_info;
	size_t len        = 0;
        bool bLogerServer = true;
        int dummyStrLen   = 0,
            retval        = 0,
            logerport     = 0,
            logeruse      = 0;

	int retry_count = 0;

	char sLogFileFullPath[1024] = {0};
	char * sDataJsonLog = NULL;
	char sHeaderData[128] = {0,};

	/*
		#define HEADER_PAM_AGENT_ID     '7'
		#define HEADER_PAM_MESSG_CODE   '6'
	*/
	
	memset (header.sReqTraceId, sizeof (header.sReqTraceId), 0x00 );
	header.sAgentId = HEADER_PAM_AGENT_ID;
	header.iMsgType = HEADER_PAM_MSG_REQ_TYPE;
	header.iMsgCode = HEADER_PAM_MESSG_CODE; 
	sprintf ((char *)header.iMsgVer, "%s", ND_PAM_VERSION);

	header.sAgentId         = htons(header.sAgentId);

	const char *log_file = getPambaklogFilePath(product_nm ); 

	snprintf (sLogFileFullPath, sizeof (sLogFileFullPath), "%s_archive_%04d%02d%02d_%02d%02d%02d%s",log_file ,t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec,LOGFILE_EXTENSION);

	char * loger_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERIP);          // SERVER_IP
        char * loger_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERPORT);        // SERVER_PORT
        char * loger_server_use  = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERUSE);         // SERVER_USE

        if (    loger_server_ip         == NULL ||
                loger_server_port       == NULL ||
                loger_server_use        == NULL)
        {
                bLogerServer = false;
        }

        else
        {
                logerport       = atoi (loger_server_port);
                if (strcmp (loger_server_use, CONF_VALUE_YES) == 0)
                        logeruse = true;
                else
                        logeruse = false;
        }

	if (g_sDataHiwareUserNumber )
	{
		snprintf (logitem.userNo, sizeof (logitem.userNo), "%s", g_sDataHiwareUserNumber);
	}else
	{
		g_sDataHiwareUserNumber = getenv ("HIWARE_USER_NUMBER");
		if (g_sDataHiwareUserNumber)
			snprintf (logitem.userNo, sizeof (logitem.userNo), "%s", g_sDataHiwareUserNumber);
	}

	sDataJsonLog = create_pam_archivelogdate_using_JSON(logitem);
	for (retry_count = 0; retry_count < MAX_RETRY_COUNT; retry_count++)     {

                retval = sending_data_to_logger(header.sAgentId, header.iMsgType, header.iMsgCode, ND_PAM_VERSION, sDataJsonLog);
                if (retval == 0) {
                        nd_log(NDLOG_TRC, "nd_pam_sulog_to_JSON SEND LOGGER..SUCCESS");
                        free(sDataJsonLog);
                        return; // 성공 시 바로 종료
                }
        }

        header.iMsgTotalSize = htonl(strlen(sDataJsonLog));

	nd_pam_write_back_log(sLogFileFullPath, &header, sDataJsonLog);

        free (sDataJsonLog);
}

void nd_pam_write_back_log(char* file_name,struct _msg_header_ * header, char * body_data)
{
	FILE *file = fopen(file_name, "ab+");
	if (file == NULL)
		return;

	size_t written = fwrite(header, sizeof (struct _msg_header_), 1, file);
	if (written != 1)	{
		fclose(file);
		return;
	}

	fprintf(file, "%s", body_data);

	fclose(file);
}

void nd_pam_log_to_JSON(struct _msg_header_ header,char * product_nm, char * agtAuthNo, char* agtId,  char* action_type, char* session_status, char * current_user, char * ipAddress, char * sessionKey, char * log_result_data, char *fmt, ... )
{
        size_t len        = 0;
        bool bLogerServer = true;
        int dummyStrLen   = 0,
            retval        = 0,
            logerport     = 0,
            logeruse      = 0;

        va_list args;
        char sLogMsg[1024]       = {0,},
             sBakStr[1024]       = {0,},
             sDummStr[1024]      = {0,},
             sDummySizeString[8] = {0,};

	char * sFileLogData = NULL;
        char * sDataJsonLog = NULL;
	time_t now = time(NULL);
        struct tm *t = localtime(&now);
	char sLogFileFullPath[1024] = {0};
	char sHeaderData[128] = {0,};


        /*
                // /<product name>/data/nda-pam-backup.log
        */
        const char *log_file = getPambaklogFilePath(product_nm ); //PAM_BACKUP_LOG_FILE;

	snprintf (sLogFileFullPath, sizeof (sLogFileFullPath), "%s_%04d%02d%02d_%02d%02d%02d%s",log_file ,t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec,LOGFILE_EXTENSION);

	syslog (LOG_ERR, "sLogFileFullPath : %s", sLogFileFullPath);
        /*
                //get conf information
        */
        char * loger_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERIP);          // SERVER_IP
        char * loger_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERPORT);        // SERVER_PORT
        char * loger_server_use  = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERUSE);         // SERVER_USE

        if (    loger_server_ip         == NULL ||
                loger_server_port       == NULL ||
                loger_server_use        == NULL)
        {
                bLogerServer = false;
        }

        else
        {
                logerport       = atoi (loger_server_port);
                if (strcmp (loger_server_use, CONF_VALUE_YES) == 0)
                        logeruse = true;
                else
                        logeruse = false;
        }

        /*
                // Application of usage based on configuration settings
        */
        bLogerServer = logeruse;

        /*
                //Decide to send logs after confirming server access.
        */
        if (bLogerServer)
                bLogerServer = check_server_connection (loger_server_ip, logerport);

        if (!bLogerServer)
                nd_log (NDLOG_ERR, "[PREFIX ERR CODE] cannot access the log collection server. (%s/%d)", loger_server_ip, logerport );

        va_start(args, fmt);
        vsnprintf (sBakStr, sizeof (sBakStr), fmt, args);

        va_end(args);

        header.iMsgTotalSize = 0;

        sDataJsonLog = create_pamlogdata_using_JSON (agtAuthNo, agtId, action_type, session_status, current_user, ipAddress, sessionKey, sBakStr);

        if (bLogerServer)
        {
                /*
                        // Send logs to the log server and do not store them locally.
                */
                retval = sending_data_to_logger((char*)header.sAgentId,header.iMsgType, header.iMsgCode, /*header.iMsgVerMaj,header.iMsgVerMin*/header.iMsgVer, sDataJsonLog );

                if (retval == 0)
                {
                        free (sDataJsonLog);
                        return;
                }
        }

	header.iMsgTotalSize = strlen (sDataJsonLog) + sizeof (struct _msg_header_) ;

        nd_log (NDLOG_INF, "cannot access the log collection service, save the backup logs locally.");

#ifdef _INCLUDE_FILE_LOCK
        /*
                //open lock file
                // /<product name>/data/nda-pam-backup.lock
        */
        int lock_fd = open(PAM_BACKUP_LOG_LOCK_FILE, O_CREAT | O_RDWR, 0644);
        if (lock_fd == -1) {
                return;
        }

        /*
                //lock the file
        */
        if (flock(lock_fd, LOCK_EX) == -1) {
                nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to lock the log file");
                close(lock_fd);
                return;
        }
#endif //_INCLUDE_FILE_LOCK
        /*
                // Store the log message in log_result_data if needed
        */

	/*
		// [20241205-COSMOS] add header data to File log data
	*/
#ifdef _OLD_SRC	
        strncpy(log_result_data, sDataJsonLog, MAX_STRING_LENGTH - 1);
        log_result_data[MAX_STRING_LENGTH - 1] = '\0'; // Ensure null termination

	sFileLogData = (char *)malloc (strlen(sDataJsonLog) + sizeof (sHeaderData));
	if (sFileLogData == NULL )	{
		// error msg
		return;
	}

	sprintf (sHeaderData, "{ \"header\": { \"ProductType\": %d, \"MsgType\": %d, \"MsgCode\": %d, \"MsgVerMaj\": %d, \"MsgVerMin\": %d, \"MsgTotalSize\": %d },", 
		header.iProductType, header.iMsgType, header.iMsgCode, header.iMsgVerMaj,header.iMsgVerMin, header.iMsgTotalSize); 

	snprintf (sFileLogData, strlen(sDataJsonLog) + sizeof (sHeaderData), "%s%s", sHeaderData, sDataJsonLog +1);
#endif //_OLD_SRC

	nd_pam_write_back_log(sLogFileFullPath, &header, sDataJsonLog);

#ifdef _OLD_SRC
        FILE *file = fopen(sLogFileFullPath, "a");
        if (file) {

                //fprintf(file, "%s\n", sDataJsonLog);
		fprintf (file, "%s\n", sFileLogData);
                fclose(file);
        }
	free (sFileLogData);
#endif //_OLD_SRC

        free (sDataJsonLog);

#ifdef _INCLUDE_FILE_LOCK
        /*
                // unlock the file
        */
        if (flock(lock_fd, LOCK_UN) == -1) {
                //perror("Failed to unlock the log file");
                nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to unlock the log file");
        }

        close(lock_fd);
#endif //_INCLUDE_FILE_LOCK
}


void nd_pam_sulog_to_JSON(struct _msg_header_ header,char * product_nm,  char * agtAuthNo, char* agtId,char * account, char * switch_account, char * su_command, char * client_ip, char * sessionkey, char* collectlogbuffer)
{
        /*
                // /<product name>/data/nda-pam-sulog-backup.dat
        */
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
        const char *log_file = getPambakSulogFilePath( product_nm);//PAM_BACKUP_SULOG_FILE;
	char sLogFileFullPath[1024] = {0};
        bool bLogerServer = true;
        char sLogMsg[1024] = {0,}, sDummStr[1024] = {0,}, sDummySizeString[8] = {0,} ;
        int retval        = 0,
            logerport     = 0,
            logeruse      = 0;

        char * sDataJsonLog = NULL;
	//char * sFileLogData = NULL;
	//char sHeaderData[128] = {0,};

	snprintf (sLogFileFullPath, sizeof (sLogFileFullPath), "%s_%04d%02d%02d_%02d%02d%02d%s",log_file ,t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec,LOGFILE_EXTENSION);


        /*
                //get conf information
        */
        char * loger_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERIP);          // SERVER_IP
        char * loger_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERPORT);        // SERVER_PORT
        char * loger_server_use  = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERUSE);         // SERVER_USE

        if (    loger_server_ip         == NULL ||
                loger_server_port       == NULL ||
                loger_server_use        == NULL)
        {
                bLogerServer = false;
        }

        else
        {
                logerport       = atoi (loger_server_port);
                if (strcmp (loger_server_use, CONF_VALUE_YES) == 0)
                        logeruse = true;
                else
                        logeruse = false;
        }

        /*
                // Application of usage based on configuration settings
        */
        bLogerServer = logeruse;

        /*
                //Decide to send logs after confirming server access.
        */
        if (bLogerServer)
                bLogerServer = check_server_connection (loger_server_ip, logerport);

        sDataJsonLog = create_sulogdata_using_JSON (agtAuthNo, agtId,  account, switch_account, su_command, client_ip, (long)time(NULL), sessionkey);



        if (bLogerServer)
        {
		syslog (LOG_ERR, "nd_pam_sulog_to_JSON SEND LOGGER..");
                /*
                        // Send logs to the log server and do not store them locally.
                */

                retval = sending_data_to_logger((char*)header.sAgentId, header.iMsgType, header.iMsgCode, ND_PAM_VERSION/*header.iMsgVerMaj,header.iMsgVerMin*/, sDataJsonLog );
                if (retval == 0 )
                {
                        free (sDataJsonLog);
                        return;
                }
        }
#ifdef _INCLUDE_FILE_LOCK
        /*
                // open lock file
                // /<product name>/data/nda-pam-sulog-backup.lock
        */
        int lock_fd = open(PAM_BACKUP_SULOG_LOCK_FILE, O_CREAT | O_RDWR, 0644);
        if (lock_fd == -1) {
                nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to open lock file");
                return;
        }

        /*
                // lock the file
        */
        if (flock(lock_fd, LOCK_EX) == -1) {
                nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to lock the log file");
                close(lock_fd);
                return;
        }
#endif //_INCLUDE_FILE_LOCK

        /*
                // Store the log message in log_result_data if needed
        */
        snprintf (collectlogbuffer, sizeof (sLogMsg), sDataJsonLog);

	header.iMsgTotalSize = strlen (sDataJsonLog)/* + sizeof (struct _msg_header_) */;

#ifdef _OLD_SRC
	sFileLogData = (char *)malloc (strlen(sDataJsonLog) + sizeof (sHeaderData));
        if (sFileLogData == NULL )      {
                // error msg
        }

	sprintf (sHeaderData, "{ \"header\": { \"ProductType\": %d, \"MsgType\": %d, \"MsgCode\": %d, \"MsgVerMaj\": %d, \"MsgVerMin\": %d, \"MsgTotalSize\": %d },",
                header.iProductType, header.iMsgType, header.iMsgCode, header.iMsgVerMaj,header.iMsgVerMin, header.iMsgTotalSize);

        snprintf (sFileLogData, strlen(sDataJsonLog) + sizeof (sHeaderData), "%s%s", sHeaderData, sDataJsonLog +1);


        FILE *file = fopen(sLogFileFullPath, "a");
        if (file) {

                //fprintf(file, "%s\n", sDataJsonLog);
		fprintf (file, "%s\n", sFileLogData);
                fclose(file);
        }

	free (sFileLogData);
#endif //_OLD_SRC

	nd_pam_write_back_log(sLogFileFullPath, &header, sDataJsonLog);

        free (sDataJsonLog);
#ifdef _INCLUDE_FILE_LOCK
        /*
                //unlock the file
        */ 
        if (flock(lock_fd, LOCK_UN) == -1) {
                nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to unlock the log file");
        }

        close(lock_fd);
#endif //_INCLUDE_FILE_LOCK

}


void nd_pam_session_log_to_JSON(struct _msg_header_ header, char * product_nm, char * agtAuthNo, char* agtId, char *prefix, char* session_id, char* account, int uid, int gid, bool isConsole, char* ipAddr, long _time, char * session_key, char* collectlogbuff)
{
	time_t now = time(NULL);
        struct tm *t = localtime(&now);
        //char timestamp[50];
        bool bLogerServer = true;
        //size_t len;
        //va_list args;
	
	char sLogFileFullPath[1024] = {0};
                
        /*
                // /<product name>/data/nda-pam-session-backup.log
        */
        const char *log_file = getPambakSessionlogFilePath(product_nm ); //PAM_BACKUP_SESSION_LOG_FILE;

        char    sLogMsg[1024]  = {0,};
                //sDummStr[1024] = {0,};
                //sDummySizeString[8] = {0,};

        char * sDataJsonLog = NULL;
	//char * sFileLogData = NULL;
        //char sHeaderData[128] = {0,};


        int retval        = 0,
            logerport     = 0,
            logeruse      = 0;

	snprintf (sLogFileFullPath, sizeof (sLogFileFullPath), "%s_%04d%02d%02d_%02d%02d%02d%s",log_file ,t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec,LOGFILE_EXTENSION);

        /*
                //get conf information
        */
        char * loger_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERIP);          // SERVER_IP
        char * loger_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERPORT);        // SERVER_PORT
        char * loger_server_use  = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERUSE);         // SERVER_USE

        if (    loger_server_ip         == NULL ||
                loger_server_port       == NULL ||
                loger_server_use        == NULL)
        {
                bLogerServer = false;
        }

        else
        {
                logerport       = atoi (loger_server_port);
                if (strcmp (loger_server_use, CONF_VALUE_YES) == 0)
                        logeruse = true;
                else
                        logeruse = false;
        }


        /*
                // Application of usage based on configuration settings
        */
        bLogerServer = logeruse;

        /*
                //Decide to send logs after confirming server access.
        */
        if (bLogerServer)
                bLogerServer = check_server_connection (loger_server_ip, logerport);



        sDataJsonLog = create_sessionlogdata_using_JSON (agtAuthNo, agtId, prefix,session_id,account,uid,gid,isConsole,ipAddr,_time,session_key);

        if (bLogerServer)
        {
		syslog (LOG_ERR, "nd_pam_session_log_to_JSON SEND LOGGER..");
                /*
                        // Send logs to the log server and do not store them locally.
                */

                retval = sending_data_to_logger(header.sAgentId, header.iMsgType, header.iMsgCode, /*header.iMsgVerMaj,header.iMsgVerMin*/ND_PAM_VERSION, sDataJsonLog );
                if (retval == 0)
                {
                        free (sDataJsonLog);
                        return;
                }
        }
#ifdef _INCLUDE_FILE_LOCK

        /*
                // open the lock file
                // /<product name>/data/nda-pam-session-backup.lock
        */
        int lock_fd = open(PAM_BACKUP_SESSION_LOCK_LOG_FILE, O_CREAT | O_RDWR, 0644);
        if (lock_fd == -1) {
                nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to open lock file");
                return;
        }

        /*
                // lock the file
        */
        if (flock(lock_fd, LOCK_EX) == -1) {
                nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to lock the log file");
                close(lock_fd);
                return;
        }
#endif //_INCLUDE_FILE_LOCK
        /*
                // Store the log message in log_result_data if needed
        */
        snprintf (collectlogbuff, sizeof (sLogMsg), sDataJsonLog);

	header.iMsgTotalSize = strlen (sDataJsonLog)/* + sizeof (struct _msg_header_)*/ ;

#ifdef _OLD_SRC
	sFileLogData = (char *)malloc (strlen(sDataJsonLog) + sizeof (sHeaderData));
        if (sFileLogData == NULL )      {
                // error msg
        }


	sprintf (sHeaderData, "{ \"header\": { \"ProductType\": %d, \"MsgType\": %d, \"MsgCode\": %d, \"MsgVerMaj\": %d, \"MsgVerMin\": %d, \"MsgTotalSize\": %d },",
                header.iProductType, header.iMsgType, header.iMsgCode, header.iMsgVerMaj,header.iMsgVerMin, header.iMsgTotalSize);

        snprintf (sFileLogData, strlen(sDataJsonLog) + sizeof (sHeaderData), "%s%s", sHeaderData, sDataJsonLog +1);


        FILE *file = fopen(sLogFileFullPath, "a");
        if (file) {

                //fprintf(file, "%s\n", sDataJsonLog);
		fprintf(file, "%s\n", sFileLogData);
                fclose(file);
        }

	free (sFileLogData);
#endif //_OLD_SRC

	nd_pam_write_back_log(sLogFileFullPath, &header, sDataJsonLog);

        free (sDataJsonLog);

#ifdef _INCLUDE_FILE_LOCK
        // unlock the file
        if (flock(lock_fd, LOCK_UN) == -1) {
                nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to unlock the log file");
        }

        close(lock_fd);
#endif //_INCLUDE_FILE_LOCK
}



void nd_pam_log(struct _msg_header_ header, char * product_nm, char * agtAuthNo, char* agtId,  char* action_type, char* session_status, char * current_user, char * ipAddress, char * sessionKey, char * log_result_data, char *fmt, ... )
{
	va_list args;
        char * trans_format_type = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_TRANS_FORMAT);          // SERVER_IP
#ifndef _OLD_SRC_
	va_start(args, fmt);
        nd_pam_log_to_JSON(header,product_nm, agtAuthNo, agtId, action_type, session_status, current_user, ipAddress, sessionKey, log_result_data, fmt,args);
        va_end(args);
        return;
#else
        if (trans_format_type != NULL && strcmp (trans_format_type, CONF_VALUE_JSON) == 0 )
        {
		va_start(args, fmt);
                nd_pam_log_to_JSON(header,product_nm, agtAuthNo, agtId, action_type, session_status, current_user, ipAddress, sessionKey, log_result_data, fmt,args);
		va_end(args);
                return;
        }

        else
        {
                size_t len        = 0;
                bool bLogerServer = true;
                int dummyStrLen   = 0,
                    retval        = 0,
                    logerport     = 0,
                    logeruse      = 0;

                char sLogMsg[1024]       = {0,},
                     sBakStr[1024]       = {0,},
                     sDummStr[1024]      = {0,},
                     sDummySizeString[8] = {0,};

                /*
                        // /<product name>/data/nda-pam-backup.log
                */
                const char *log_file = PAM_BACKUP_LOG_FILE;

                /*
                        //get conf information
                */
                char * loger_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERIP);          // SERVER_IP
                char * loger_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERPORT);        // SERVER_PORT
                char * loger_server_use  = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERUSE);         // SERVER_USE

                if (    loger_server_ip         == NULL ||
                        loger_server_port       == NULL ||
                        loger_server_use        == NULL)
                {
                        bLogerServer = false;
                }

                else
                {
                        logerport       = atoi (loger_server_port);
                        if (strcmp (loger_server_use, CONF_VALUE_YES) == 0)
                                logeruse = true;
                        else
                                logeruse = false;
                }

                /*
                        // Application of usage based on configuration settings
                */
                bLogerServer = logeruse;

                /*
                        //Decide to send logs after confirming server access.
                */
                if (bLogerServer)
                        bLogerServer = check_server_connection (loger_server_ip, logerport);

                va_start(args, fmt);
                vsnprintf (sBakStr, sizeof (sBakStr), fmt, args);
                va_end(args);

                header.iMsgTotalSize = 0;

                /*
                        // step 1
                */
                snprintf (sDummStr, sizeof (sDummStr), ND_PAMLOG_FORMAT_V2, header.iMsgType, header.iMsgCode, /*header.iMsgVerMaj, header.iMsgVerMin*/ND_PAM_VERSION, header.iMsgTotalSize,
                        action_type, session_status, current_user, ipAddress, sessionKey, sBakStr);


                if (sDummStr[strlen(sDummStr) -1] == '\n')
                        sDummStr[strlen(sDummStr) -1] = '\0';

                /*
                        // step 2
                */
                sprintf(sDummySizeString, "%d", strlen(sDummStr)-1);
                dummyStrLen = strlen (sDummySizeString);

                header.iMsgTotalSize = dummyStrLen + MSG_HEADER_SIZE + (strlen(sDummStr)-1) ;

                /*
                        //
                */
                snprintf (sLogMsg, sizeof (sLogMsg), ND_PAMLOG_FORMAT_V2, header.iMsgType, header.iMsgCode, /*header.iMsgVerMaj, header.iMsgVerMin*/ND_PAM_VERSION, header.iMsgTotalSize,
                       action_type,  session_status, current_user, ipAddress, sessionKey, sBakStr);

                if (sLogMsg[strlen(sLogMsg) -1] == '\n')
                        sLogMsg[strlen(sLogMsg) -1] = '\0';

                if (bLogerServer)
                {
                        /*
                                // Send logs to the log server and do not store them locally.
                        */
                        retval = sending_data_to_logger(header.sAgentId, header.iMsgType, header.iMsgCode,/* header.iMsgVerMaj,header.iMsgVerMin*/ND_PAM_VERSION, sLogMsg );

                        if (retval == 0)
                                return;
                }

                /*
                        // Store the log message in log_result_data if needed
                */
                strncpy(log_result_data, sLogMsg, MAX_STRING_LENGTH - 1);
                log_result_data[MAX_STRING_LENGTH - 1] = '\0'; // Ensure null termination

                /*
                        //open lock file
                        // /<product name>/data/nda-pam-backup.lock
                */
                int lock_fd = open(PAM_BACKUP_LOG_LOCK_FILE, O_CREAT | O_RDWR, 0644);
                if (lock_fd == -1) {
                        return;
                }

                /*
                        //lock the file
                */
                if (flock(lock_fd, LOCK_EX) == -1) {
                        nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to lock the log file");
                        close(lock_fd);
                        return;
                }

                FILE *file = fopen(log_file, "a");
                if (file) {

                        fprintf(file, "%s\n", sLogMsg);
                        fclose(file);
                }
                /*
                        // unlock the file
                */
                if (flock(lock_fd, LOCK_UN) == -1) {
                        nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to unlock the log file");
                }

                close(lock_fd);
        }
#endif 
}


void nd_pam_sulog(struct _msg_header_ header, char * product_nm, char * agtAuthNo, char* agtId,  char * account, char * switch_account, char * su_command, char * client_ip, char * sessionkey, char* collectlogbuffer)
{
        char * trans_format_type = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_TRANS_FORMAT);          // SERVER_IP

#ifndef _OLD_SRC_
	nd_pam_sulog_to_JSON(header,product_nm, agtAuthNo, agtId,  account, switch_account, su_command, client_ip, sessionkey, collectlogbuffer);
        return;
#else
        if (trans_format_type != NULL && strcmp (trans_format_type, CONF_VALUE_JSON) == 0 )
        {
                nd_pam_sulog_to_JSON(header,product_nm, agtAuthNo, agtId,  account, switch_account, su_command, client_ip, sessionkey, collectlogbuffer);

                return;
        }

        else
        {
                /*
                        // /<product name>/data/nda-pam-sulog-backup.log
                */
                const char *log_file = PAM_BACKUP_SULOG_FILE;
                bool bLogerServer = true;
                char sLogMsg[1024] = {0,}, sDummStr[1024] = {0,}, sDummySizeString[8] = {0,} ;
                int dummyStrLen   = 0,
                    retval        = 0,
                    logerport     = 0,
                    logeruse      = 0;


                /*
                        //get conf information
                */
                char * loger_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERIP);          // SERVER_IP
                char * loger_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERPORT);        // SERVER_PORT
                char * loger_server_use  = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERUSE);         // SERVER_USE

                if (    loger_server_ip         == NULL ||
                        loger_server_port       == NULL ||
                        loger_server_use        == NULL)
                {
                        bLogerServer = false;
                }

                else
                {
                        logerport       = atoi (loger_server_port);
                        if (strcmp (loger_server_use, CONF_VALUE_YES) == 0)
                                logeruse = true;
                        else
                                logeruse = false;
                }

                /*
                        // Application of usage based on configuration settings
                */
                bLogerServer = logeruse;

                /*
                        //Decide to send logs after confirming server access.
                */
                if (bLogerServer)
                        bLogerServer = check_server_connection (loger_server_ip, logerport);



                /*
                        // step 1
                */
                 snprintf (sDummStr, sizeof (sDummStr), ND_SULOG_FORMAT_V2,header.iMsgType, header.iMsgCode,/* header.iMsgVerMaj, header.iMsgVerMin*/ND_PAM_VERSION, header.iMsgTotalSize,
                        account, switch_account, su_command, client_ip, (long)time(NULL), sessionkey );

                if (sDummStr[strlen(sDummStr) -1] == '\n')
                        sDummStr[strlen(sDummStr) -1] = '\0';

                sprintf(sDummySizeString, "%d", strlen(sDummStr)-1);
                dummyStrLen = strlen (sDummySizeString);

                header.iMsgTotalSize = dummyStrLen + MSG_HEADER_SIZE + (strlen(sDummStr)-1) ;

                /*
                        // step 2
                */
                snprintf (sLogMsg, sizeof (sLogMsg), ND_SULOG_FORMAT_V2,header.iMsgType, header.iMsgCode,/* header.iMsgVerMaj, header.iMsgVerMin*/ND_PAM_VERSION, header.iMsgTotalSize,
                        account, switch_account, su_command, client_ip, (long)time(NULL), sessionkey );

                if (sLogMsg[strlen(sLogMsg) -1] == '\n')
                        sLogMsg[strlen(sLogMsg) -1] = '\0';

                if (bLogerServer)
                {
                        /*
                                // Send logs to the log server and do not store them locally.
                        */

                        retval = sending_data_to_logger(header.sAgentId, header.iMsgType, header.iMsgCode, /*header.iMsgVerMaj,header.iMsgVerMin*/ND_PAM_VERSION, sLogMsg );
                        if (retval == 0 )
                                return;
                }

                /*
                        // Store the log message in log_result_data if needed
                */
                snprintf (collectlogbuffer, sizeof (sLogMsg), sLogMsg);

                /*
                        //open lock file
                        // /<product name>/data/nda-pam-sulog-backup.lock
                */
                int lock_fd = open(PAM_BACKUP_SULOG_LOCK_FILE, O_CREAT | O_RDWR, 0644);
                if (lock_fd == -1) {
                        return;
                }

                /*
                        //lock the file
                */
                if (flock(lock_fd, LOCK_EX) == -1) {
                        nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to lock the log file");
                        close(lock_fd);
                        return;
                }

                FILE *file = fopen(log_file, "a");
                if (file) {

                        fprintf(file, "%s\n", sLogMsg);
                        fclose(file);
                }

                /*
                        // unlock the file
                */
                if (flock(lock_fd, LOCK_UN) == -1) {
                        nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to unlock the log file");
                }

                close (lock_fd);
        }
#endif
}


void nd_pam_session_log(struct _msg_header_ header, char * product_nm, char * agtAuthNo, char* agtId,  char *prefix, char* session_id, char* account, int uid, int gid, bool isConsole, char* ipAddr, long time, char * session_key, char* collectlogbuff)
 {

        char * trans_format_type = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_TRANS_FORMAT);          // SERVER_IP
#ifndef _OLD_SRC_
	nd_pam_session_log_to_JSON(header, product_nm, agtAuthNo, agtId,  prefix, session_id, account, uid, gid, isConsole, ipAddr, time, session_key, collectlogbuff);
        return;

#else
        if (trans_format_type != NULL && strcmp (trans_format_type, CONF_VALUE_JSON) == 0 )
        {
                nd_pam_session_log_to_JSON(header, product_nm, agtAuthNo, agtId,  prefix, session_id, account, uid, gid, isConsole, ipAddr, time, session_key, collectlogbuff);

                return;
        }

        else
        {
                char timestamp[50];
                bool bLogerServer = true;
                size_t len;
                va_list args;

                /*
                        // /<product name>/data/nda-pam-session-backup.log
                */
                const char *log_file = PAM_BACKUP_SESSION_LOG_FILE;

                char    sLogMsg[1024]  = {0,},
                        sDummStr[1024] = {0,},
                        sDummySizeString[8] = {0,};

                int dummyStrLen   = 0,
                    retval        = 0,
                    logerport     = 0,
                    logeruse      = 0;


                /*
                        //get conf information
                */
                char * loger_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERIP);          // SERVER_IP
                char * loger_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERPORT);        // SERVER_PORT
                char * loger_server_use  = get_value_from_inf(g_sConfFilePath, SECTION_NM_HILOGER_CONF, PAM_CONF_KEY_SERVERUSE);         // SERVER_USE

                if (    loger_server_ip         == NULL ||
                        loger_server_port       == NULL ||
                        loger_server_use        == NULL)
                {
                        bLogerServer = false;
                }

                else
                {
                        logerport       = atoi (loger_server_port);
                        if (strcmp (loger_server_use, CONF_VALUE_YES) == 0)
                                logeruse = true;
                        else
                                logeruse = false;
                }

                /*
                        // Application of usage based on configuration settings
                */
                bLogerServer = logeruse;

                /*
                        //Decide to send logs after confirming server access.
                */
                if (bLogerServer)
                        bLogerServer = check_server_connection (loger_server_ip, logerport);



                /*
                        // step 1
                */
                snprintf (sDummStr, sizeof (sDummStr), ND_SESSIONLOG_FORMAT_V2, header.iMsgType, header.iMsgCode, /*header.iMsgVerMaj, header.iMsgVerMin*/ND_PAM_VERSION, header.iMsgTotalSize,
                                prefix, session_id, account, uid, gid, isConsole, ipAddr, time, session_key);
                if (sDummStr[strlen(sDummStr) -1] == '\n')
                        sDummStr[strlen(sDummStr) -1] = '\0';

                sprintf(sDummySizeString, "%d", strlen(sDummStr)-1);
                dummyStrLen = strlen (sDummySizeString);

                header.iMsgTotalSize = dummyStrLen + MSG_HEADER_SIZE + (strlen(sDummStr)-1) ;

                /*
                        // step 2
                */
                snprintf (sLogMsg, sizeof (sLogMsg), ND_SESSIONLOG_FORMAT_V2, header.iMsgType, header.iMsgCode, /*header.iMsgVerMaj, header.iMsgVerMin*/ND_PAM_VERSION, header.iMsgTotalSize,
                                prefix, session_id, account, uid, gid, isConsole, ipAddr, time, session_key);
                if (sLogMsg[strlen(sLogMsg) -1] == '\n')
                        sLogMsg[strlen(sLogMsg) -1] = '\0';

                if (bLogerServer)
                {
                        /*
                                // Send logs to the log server and do not store them locally.
                        */

                        retval = sending_data_to_logger(header.sAgentId, header.iMsgType, header.iMsgCode, /*header.iMsgVerMaj,header.iMsgVerMin*/ND_PAM_VERSION, sLogMsg );
                        if (retval == 0)
                                return;
                }


                /*
                        // Store the log message in log_result_data if needed
                */
                snprintf (collectlogbuff, sizeof (sLogMsg), sLogMsg);

                /*
                        //open lock file
                        // /<product name>/data/nda-pam-session-backup.lock
                */
                int lock_fd = open(PAM_BACKUP_SESSION_LOCK_LOG_FILE, O_CREAT | O_RDWR, 0644);
                if (lock_fd == -1) {
                        return;
                }

                /*
                        //lock the file
                */
                if (flock(lock_fd, LOCK_EX) == -1) {
                        nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to lock the log file");
                        close(lock_fd);
                        return;
                }


                FILE *file = fopen(log_file, "a");
                if (file) {

                        fprintf(file, "%s\n", sLogMsg);
                        fclose(file);
                }

                /*
                        // unlock the file
                */
                if (flock(lock_fd, LOCK_UN) == -1) {
                        nd_log (NDLOG_ERR, "[PREFIX ERR CODE] Failed to unlock the log file");
                }

                close (lock_fd);
        }

#endif
}

/*
 	//pam log
	//Function to log messages in the PAM module.
*/
void nd_pam_devlog(int level, char* filename, int line, const char *fmt, ...)	{

        int nSettingLevel = 0;
	char timestamp[50];
	va_list args;
	struct stat st = {0,};
	char sLogFileFullPath[1024] = {0};
	char sLogMsg[1024] = {0,}, sBakStr[1024] = {0,};

	snprintf (sLogFileFullPath, sizeof (sLogFileFullPath), "%s/%s", getPamLogFilePath(), DEBUG_LOG_FILE);

	if (access(sLogFileFullPath, F_OK) != 0) { 
		
		if (stat(getPamLogFilePath(), &st) == -1)
		{
			if (mkdir (getPamLogFilePath(), 0755) != 0 && errno != EEXIST)	{
				//ERROR
				return;
			}
		}

		// file not exist
		int fd = open (sLogFileFullPath, O_CREAT | O_WRONLY, 0644);	
		if (fd == -1)
			return;

		close (fd);
	}

        char * log_level   = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF, PAM_LOG_MODE);

        //nd_log_level
        for (int i = 0 ; i < NDLOG_MAX ; i ++ )
        {
                if (strcmp (nd_log_level[i].stLevel, log_level) == 0 )
                {
                        nSettingLevel = i;
                        break;
                }
        }

        if (nSettingLevel < level && level != NDLOG_ERR)
        {
		syslog (LOG_ERR , "test --001");
		
                return;
        }


	get_timestamp(timestamp, sizeof (timestamp));
	va_start(args, fmt);
	vsnprintf (sBakStr, sizeof (sBakStr), fmt, args);
	va_end(args);

	snprintf (sLogMsg, sizeof (sLogMsg), "%s(%s) <%s:%d>    %s\n",timestamp, nd_log_level[level].stLevel, filename, line, sBakStr);

	if (sLogMsg[strlen(sLogMsg) -1] == '\n')
		sLogMsg[strlen(sLogMsg) -1] = '\0';

	FILE *file = fopen(sLogFileFullPath, "a");
	if (file) {

		fprintf(file, "%s\n", sLogMsg);
		fclose(file);
	} 
}
