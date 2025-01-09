#include <syslog.h>
#include <ctype.h>

#include "nd_restapi_func.h"
#include <time.h>
#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
//#include <openssl/core_names.h>
#include <curl/curl.h>
#include <stdbool.h>
#include <locale.h>
#include <iconv.h>

#include "../common.h"
#include "nd_utils.h"
#include "nd_nix_logs.h"

/*
	//
*/
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

	//
	///
	nd_log (NDLOG_TRC, "MakeRdmURL::rdmURL = %s", rdmURL);
}

/*
	//
*/
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

	//
        ///
        nd_log (NDLOG_TRC, "MakeLoginURL::loginURL = %s", loginURL);
}

void MakeUserLoginURL(const char *ip, int port, char *loginURL, size_t loginURLSize, int httpsUse)	{

	char url[1024];

	if (httpsUse == 0 )	{
		snprintf(url, sizeof(url), "http://%s:%d%s", ip, port, STRING_USERLOGIN_URI);
	} else	{
		snprintf(url, sizeof(url), "https://%s:%d%s", ip, port, STRING_USERLOGIN_URI);
	}

	// Copy the generated URL to rdmURL
        strncpy(loginURL, url, loginURLSize - 1);
        loginURL[loginURLSize - 1] = '\0';  // Add a null termination character at the end

	//
        ///
	/*
	nd_log (NDLOG_TRC, "====================================================================");
        nd_log (NDLOG_TRC, " USER-LOGIN URL");
        nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
	*/
        nd_log (NDLOG_TRC, " * request user login url : %s", loginURL);
	//nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
}

void MakeTwofactOtpLoginURL(const char *ip, int port, char *loginURL, size_t loginURLSize, int httpsUse)      {

        char url[1024];

        if (httpsUse == 0 )     {
                snprintf(url, sizeof(url), "http://%s:%d%s", ip, port, STRING_TWOFACT_OTP_URI);
        } else  {
                snprintf(url, sizeof(url), "https://%s:%d%s", ip, port, STRING_TWOFACT_OTP_URI);
        }

        // Copy the generated URL to rdmURL
        strncpy(loginURL, url, loginURLSize - 1);
        loginURL[loginURLSize - 1] = '\0';  // Add a null termination character at the end

	//
        ///
	/*
        nd_log (NDLOG_TRC, "====================================================================");
        nd_log (NDLOG_TRC, " MFA-LOGIN URL");
        nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
	*/
        nd_log (NDLOG_TRC, " * request mfa login url: %s", loginURL);
	//nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
}



/*
	//"https://192.168.15.205:11200/hiware/api/v1/auth/randomKey";
*/
const char* GetRdmURL()         {

	if (strlen (g_sDataRandomUrl) <= 0)
	{
		char * auth_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERIP);
        	char * auth_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERPORT);
		char * auth_server_usessl = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_AUTHSVR_USESSL);

		MakeRdmURL((const char *)auth_server_ip, atoi (auth_server_port),g_sDataRandomUrl, sizeof (g_sDataRandomUrl), (strcmp (auth_server_usessl, CONF_VALUE_YES) ? 1 : 0)); 
	}

	if (strlen (g_sDataRandomUrl) <= 0 )
		return NULL;

	//
        ///
	/*
	nd_log (NDLOG_TRC, "====================================================================");
	nd_log (NDLOG_TRC, " RANDOMURL ");
	nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
	*/
        nd_log (NDLOG_TRC, " * request random url : %s", g_sDataRandomUrl);
	//nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
	

        //return "https://192.168.15.205:11200/hiware/api/v1/auth/randomKey"; // 비밀 키를 반환하는 함수
	return g_sDataRandomUrl;
}

/*
	//https://127.0.0.1:11200/hiware/api/v1/auth/pam/login
*/
const char* GetUserLoginURL()	{
	
	if (strlen (g_sDataUserLoginUrl) <= 0 )
	{
		char * auth_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERIP);
                char * auth_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERPORT);
                char * auth_server_usessl = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_AUTHSVR_USESSL);

		MakeUserLoginURL ((const char *)auth_server_ip, atoi(auth_server_port), g_sDataUserLoginUrl, sizeof (g_sDataUserLoginUrl), (strcmp (auth_server_usessl, CONF_VALUE_YES) ? 0 : 1));
	}

	//
        ///
	/*
        nd_log (NDLOG_TRC, "====================================================================");
        nd_log (NDLOG_TRC, " GetUserLoginURL"); 
        nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
	*/
        nd_log (NDLOG_TRC, " * get user login url :%s", g_sDataUserLoginUrl ? g_sDataUserLoginUrl : "null");
	//nd_log (NDLOG_TRC, "--------------------------------------------------------------------");

	if (strlen (g_sDataUserLoginUrl) <= 0 )
		return NULL;

	return g_sDataUserLoginUrl;
}

/*
        //https://127.0.0.1:11200/hiware/api/v1/auth/pam/login
*/
const char* GetTwoFact_OtpURL()   {

        if (strlen (g_sDataTwoFactLoginIrl) <= 0 )
        {
                char * auth_server_ip   = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERIP);
                char * auth_server_port = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_CONF_KEY_SERVERPORT);
                char * auth_server_usessl = get_value_from_inf(g_sConfFilePath, SECTION_NM_HIAUTH_CONF, PAM_AUTHSVR_USESSL);

                MakeTwofactOtpLoginURL ((const char *)auth_server_ip, atoi(auth_server_port), g_sDataTwoFactLoginIrl, sizeof (g_sDataTwoFactLoginIrl), (strcmp (auth_server_usessl, CONF_VALUE_YES) ? 0 : 1));
        }

	//char g_sDataTwoFactLoginIrl[MAX_URL_LEN];

	//
	///
	/*
	nd_log (NDLOG_TRC, "====================================================================");
        nd_log (NDLOG_TRC, " GetTwoFact_OtpURL");
        nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
	*/
	nd_log (NDLOG_TRC, " * get mfa login url: %s", g_sDataTwoFactLoginIrl ? g_sDataTwoFactLoginIrl : "null");
	//nd_log (NDLOG_TRC, "--------------------------------------------------------------------");


        if (strlen (g_sDataTwoFactLoginIrl) <= 0 )
                return NULL;

        return g_sDataTwoFactLoginIrl;
}


/*
        //
*/
void setIssueKey_to_struct(Worker *worker, const char *key)     {

        worker->issueKey = strdup(key);
}

/*
        //
*/
void setRandomKey_to_struct(Worker *worker, const char *key)    {

        worker->randomKey = strdup(key);
}

/*
	//
*/
const char* getSecretKey() {

        return g_sDataSecretKey; // a function that returns the secret key
}

/*
	//
*/
void setSeretKey(char * secret_key)     {

        g_sDataSecretKey = strdup(secret_key);
}

/*
	//
*/
const char * getIssueKey()      {

        return g_sDataIssueKey;
}

/*
	//
*/
void  setIssueKey(char * issue_key)     {

        g_sDataIssueKey = strdup (issue_key);
}

/*
	//
*/
const char * getRandomKey()             {
        return g_sDataRandomKey;
}

/*
	//
*/
void setRandomKey(char * rand_key)      {

        g_sDataRandomKey = strdup (rand_key);
}

/*
	//
*/
const char * getAuthKey()               {
        return g_sDataAuthKey;
}

/*
	//
*/
void setAuthKey(char * auth_key)                {

        g_sDataAuthKey = strdup (auth_key );
}

/*
	//
*/
const char * getUserNumber()            {
        return g_sUserNumber;
}

void setUserLoginResult( char * loginResult)
{
	g_sDataUserLoginResult	= strdup(loginResult);
}

const char*  getUserLoginResult()
{
       return  g_sDataUserLoginResult;
}

void setTemporaryAccessKey( char * TempAccKey)
{
	g_sDataTemporaryAccessKey = strdup (TempAccKey);
}

const char* getTemporaryAccessKey()
{
        return g_sDataTemporaryAccessKey;
}

void setHiwareUserNumber (char  * userNumber)
{
	g_sDataHiwareUserNumber = strdup (userNumber);
}

const char * getHiwareUserNumber ()
{
	return g_sDataHiwareUserNumber;
}

/*
	//
*/
void setUserNumber(char * user_number)  {
        g_sUserNumber = strdup(user_number);
}

/*
	//
*/
char* base64UrlSafeEncode(const unsigned char *input, int length)       {

        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Remove line breaks

        BIO_write(bio, input, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        // URL-safe conversion
        char *encoded = (char *)malloc(bufferPtr->length + 1);
        memcpy(encoded, bufferPtr->data, bufferPtr->length);
        encoded[bufferPtr->length] = '\0';

        // Replace '+' with '-' and '/' with '_'.
        for (int i = 0; i < bufferPtr->length; i++)     {
                if (encoded[i] == '+')          {

                        encoded[i] = '-';
                } else if (encoded[i] == '/')   {

                    encoded[i] = '_';
                }
        }

        return encoded;
}

/*
	//
*/
char* base64_encode(const unsigned char *input, int length)     {

        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No new line

        BIO_write(bio, input, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        char *output = (char *)malloc(bufferPtr->length + 1);
        memcpy(output, bufferPtr->data, bufferPtr->length);
        output[bufferPtr->length] = '\0'; // Null-terminate the string

        return output;
}

/*
	//
*/
char* encPassword(const char *p_sStr, const char *p_sKey)       {

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        assert(ctx != NULL);

        unsigned char key[16]; // AES-128 key size
        unsigned char iv[16] = {0}; // Initialization vector (IV)
        memcpy(key, p_sKey, 16); // Assuming p_sKey is at least 16 bytes

        // Prepare the plaintext
        size_t plain_len = strlen(p_sStr);
        unsigned char *encrypted = (unsigned char *)malloc(plain_len + EVP_MAX_BLOCK_LENGTH);
        int len;
        int ciphertext_len;

        // Initialize the encryption operation
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

        // Provide the message to be encrypted, and obtain the encrypted output
        EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char *)p_sStr, plain_len);
        ciphertext_len = len;

        // Finalize the encryption
        EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
        ciphertext_len += len;

        // Base64 encode the encrypted data
        char *sData = base64_encode(encrypted, ciphertext_len);

        // Clean up
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);

        return sData;
}

/*
	//
*/
char* GetSignature(const char *sMethod, const char *url, const char *sData)     {

        const char *secretKey = getSecretKey();
        if (secretKey == NULL || strlen(secretKey) == 0)        {

		//
		///
		nd_log (NDLOG_ERR, "GetSignature::secretKey is null.");
                return NULL;
        }

        // sSrcData 생성
        size_t srcDataSize = strlen(sMethod) + strlen(url) + strlen(sData) + 3; // 3 is a space and a null character.
        char *sSrcData = (char *)malloc(srcDataSize);
        snprintf(sSrcData, srcDataSize, "%s %s%s", sMethod, url, sData);

        // Remove line breaks
        char *newlinePos;
        while ((newlinePos = strchr(sSrcData, '\n')) != NULL)   {
                *newlinePos = '\0'; // Remove line breaks
        }


        unsigned char sHash[EVP_MAX_MD_SIZE];
        unsigned int len;

        // HMAC calc
        HMAC(EVP_sha256(), secretKey, strlen(secretKey), (unsigned char *)sSrcData, strlen(sSrcData), sHash, &len);
        // Encode hash data to Base64 URL-safe
        char *sEncodeData_new = base64UrlSafeEncode(sHash, len);


        free(sSrcData);
        return sEncodeData_new; // The caller must free the memory
}

/*
	// callback function to store response data
*/
size_t callback_write_memory(void *ptr, size_t size, size_t nmemb, ApiHttpRes *res)             {

        size_t realsize = size * nmemb;
        res->m_data = realloc(res->m_data, res->size + realsize + 1);
        if (res->m_data == NULL) {
                // memory alloc fail

		//
		///
		nd_log (LOG_ERR, "callback_write_memory::realloc failed . memory alloc failed ...");
                return 0;
        }
        memcpy(&(res->m_data[res->size]), ptr, realsize);
        res->size += realsize;
        res->m_data[res->size] = '\0'; // end of string

        return realsize;
}


/*
        // login ID , login PW
*/
int getRandomKey_Request(Worker * worker)
{
        ApiHttpRes httpRes;
        SendGetDataWithDefaults ( &httpRes, GetRdmURL());

	if ( httpRes.m_data == NULL )
	{
		//
		///
		nd_log (NDLOG_ERR, "getRandomKey_Request::SendGetDataWithDefaults failed..., send data is null (httpRes.m_data is null)");

		return -1;
	}
		

	//
	///
	nd_log (NDLOG_TRC, "getRandomKey_Request::GetRdmURL() = %s", GetRdmURL());

	//
	/// 
	nd_log (NDLOG_TRC, "getRandomKey_Request::GetRandomKey result : %s", httpRes.m_data);

        int result = parse_JsonResponse_from_ramdom_request(httpRes.m_data, worker);
        if (result == RET_SUCCESS)
        {
		//
		///
		nd_log (NDLOG_TRC, "====================================================================");
		nd_log (NDLOG_TRC, " REQUEST RANDOMKEY RESULT");
		nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
                nd_log (NDLOG_TRC, "Issue Key: %s", worker->issueKey);
                nd_log (NDLOG_TRC, "Random Key: %s", worker->randomKey);
		nd_log (NDLOG_TRC, "--------------------------------------------------------------------");

                setIssueKey (worker->issueKey);
                setRandomKey (worker->randomKey);
        }
        else
        {
		//
		///
		nd_log (NDLOG_ERR, "getRandomKey_Request::parse_JsonResponse_from_ramdom_request failed.., Error occurred while parsing JSON.");
                return -1;
        }

        return 0;
}


/*
	//
*/
int SendGetData(ApiHttpRes *pRes, const char *url, const char *sSessID, const char *sSignature, const char *authKey, int iHttpsUse)
{
	CURL *curl;
        CURLcode res;
        struct curl_slist *slist = NULL;
        int bResult = 1; // Flag Indicating Success

        pRes->m_data = NULL; // initialize
        pRes->size = 0;

        curl = curl_easy_init();
        if (curl)       {

                if (iHttpsUse == 1) 	{
                        slist = curl_slist_append(slist, STRING_CURL_HEADER_USER_AGENT);			/* "User-Agent: hi-dev-checker" */	

                        if (authKey && strlen(authKey) > 0) {
                                char strAuth[256];
                                snprintf(strAuth, sizeof(strAuth), STRING_CURL_HEADER_API_TOKEN, authKey); 	/* "API-Token: %s" */
                                slist = curl_slist_append(slist, strAuth);
                        }

                        if (sSignature && strlen(sSignature) > 0) {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_SIGNATURE, sSignature); 	/*"Signature: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        if (sSessID && strlen(sSessID) > 0) {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_HANDSHAKE_SID, sSessID);	/*"Handshake-Session-Id: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
                } else          {

                        slist = curl_slist_append(slist, "Accept: */*");
                        slist = curl_slist_append(slist, "charset: utf-8");
                        slist = curl_slist_append(slist, STRING_CURL_HEADER_USER_AGENT); 			/*"User-Agent: hi-dev-checker"*/

                        if (authKey && strlen(authKey) > 0) {
                                char strAuth[256];
                                snprintf(strAuth, sizeof(strAuth), STRING_CURL_HEADER_API_TOKEN, authKey);	/*"API-Token: %s"*/
                                slist = curl_slist_append(slist, strAuth);
                        }

                        if (sSignature && strlen(sSignature) > 0) {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_SIGNATURE, sSignature);	/*"Signature: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        if (sSessID && strlen(sSessID) > 0) {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_HANDSHAKE_SID, sSessID);	/*"Handshake-Session-Id: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
                        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
                        curl_easy_setopt(curl, CURLOPT_HEADER, 0);
                }

                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, pRes);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_write_memory);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

                res = curl_easy_perform(curl);
                if (res != CURLE_OK)    {

			//
			///
			nd_log (NDLOG_ERR, "SendGetData::curl_easy_perform failed..., %s", curl_easy_strerror(res));

                        bResult = 0; // 실패
                } else {

                        if (pRes->size <= 0) {

				//
                        	///
                        	nd_log (NDLOG_ERR, "SendGetData::curl_easy_perform failed..., return success but Not find response message");

                                bResult = 0; // failed
                        }
                }

                curl_slist_free_all(slist);
                curl_easy_cleanup(curl);
        } else          {

                bResult = 0; // CURL Initialization Failed
        }

        return bResult;

}

/*
	//
*/
bool SendPostData(const char *p_sContents, ApiHttpRes *pRes, const char *url, const char *sSignature, const char *sSessID, const char *authKey, int iHttpsUse)
{
	bool bResult = true;
        CURL *curl;
        CURLcode res;

        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
        if (curl)
        {
                struct curl_slist *slist = NULL;

                // setting HTTP header
                if (iHttpsUse == 1)
                {
                        slist = curl_slist_append(slist, STRING_CURL_HEADER_CONTENT_TYPE);				/*"Content-Type: application/json"*/
                        slist = curl_slist_append(slist, STRING_CURL_HEADER_USER_AGENT);				/*"User-Agent: hi-dev-checker"*/

                        if (authKey && strlen(authKey) > 0) {
                                char strAuth[256];
                                snprintf(strAuth, sizeof(strAuth), STRING_CURL_HEADER_API_TOKEN, authKey);		/*"API-Token: %s"*/
				slist = curl_slist_append(slist, strAuth);
                        }

                        if (sSignature && strlen(sSignature) > 0) {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_SIGNATURE, sSignature);		/*"Signature: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        if (sSessID && strlen(sSessID) > 0) {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_HANDSHAKE_SID, sSessID);		/*"Handshake-Session-Id: %s*"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        struct curl_slist *current = slist;
                        while (current) {

                                current = current->next;
                        }

                        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

                } else  {


                        slist = curl_slist_append(slist, "Accept: */*");
                        slist = curl_slist_append(slist, STRING_CURL_HEADER_CONTENT_TYPE);				/*"Content-Type: application/json"*/
                        slist = curl_slist_append(slist, "charset: utf-8");
                       // slist = curl_slist_append(slist, STRING_CURL_HEADER_USER_AGENT);				/*"User-Agent: hi-dev-checker"*/

                        if (authKey && strlen(authKey) > 0) {
                                char strAuth[256];
                                snprintf(strAuth, sizeof(strAuth), "API-Token: %s", authKey);
                                slist = curl_slist_append(slist, strAuth);
                        }

                        if (sSignature && strlen(sSignature) > 0) {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_SIGNATURE, sSignature);		/*"Signature: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        if (sSessID && strlen(sSessID) > 0) {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_HANDSHAKE_SID, sSessID);		/*"Handshake-Session-Id: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
                        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
                        curl_easy_setopt(curl, CURLOPT_HEADER, 0);
                }

                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, p_sContents);

                // Response Data Processing Settings
                pRes->m_data = malloc(1); // initialize
                pRes->m_data[0] = '\0';
                pRes->size = 0;
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, pRes);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_write_memory);

                // time out setting
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                curl_easy_setopt(curl, CURLOPT_POST, 1L);

                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // disable certificate verification
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // disable host verification

                // Request Execution
                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                        fprintf(stderr, "HTTP PERFORM ERROR: %s\n", curl_easy_strerror(res));

			//
                        ///
                        nd_log (NDLOG_ERR, "SendPostData::curl_easy_perform failed..., %s", curl_easy_strerror(res));

                        bResult = false;
                } else {
                        if (pRes->size <= 0) {
                                fprintf(stderr, "HTTP RETURN Success, But Not Find Response Msg.\n");
                                bResult = false;

				//
                                ///
                                nd_log (NDLOG_ERR, "SendPostData::curl_easy_perform failed..., return success but Not find response message");
                        }
                }

                // Always Organize
                curl_slist_free_all(slist);
                curl_easy_cleanup(curl);

        } else          {

                bResult = false;
        }

        curl_global_cleanup();

        return bResult;
}


/*
	//
*/
int parse_JsonResponse_from_login_request(const char* res_doc, st_user_login_result * plogin_result)         {

	struct json_object *parsed_json = NULL, *resultCode = NULL, *content = NULL, 
                       *userNumberItem = NULL, *bool_result = NULL, *temporaryAccessKey = NULL, 
                       *errorCode = NULL, *ret_message = NULL, *hi_loginResult = NULL, 
                       *userId = NULL, *userNumber = NULL, *contentSimpleType = NULL, *state = NULL;

	if (res_doc == NULL || plogin_result == NULL) {

		//
		///
		nd_log (NDLOG_ERR, "parse_JsonResponse_from_login_request::Invalid input parameters.");
        	return EXCEPTION;
    	}

	nd_log (NDLOG_TRC, "parse_JsonResponse_from_login_request : data (%s)", res_doc);

        parsed_json = json_tokener_parse(res_doc);
        if (parsed_json == NULL) {

		//
		///
		nd_log (NDLOG_ERR, "parse_JsonResponse_from_login_request::json_tokener_parse failed..., Failed to parse JSON response.");
                return EXCEPTION;
        }

	//
	///
	nd_log (NDLOG_TRC, "====================================================================");
	nd_log (NDLOG_TRC, "[parse_JsonResponse_from_login_request::res_doc information]");
	nd_log (NDLOG_TRC, " >> res_doc : %s", res_doc);
	nd_log (NDLOG_TRC, "--------------------------------------------------------------------");

        // resultCode 추출
        if (!json_object_object_get_ex(parsed_json, "resultCode", &resultCode)) {

		//
		///
		nd_log (NDLOG_ERR, "Failed to extract the \'resultCode\' value from json.");
		
                json_object_put(parsed_json);
                return EXCEPTION;
        }

        int rCode = json_object_get_int(resultCode);
	plogin_result->resultCode = rCode;

        // content 추출
        if (!json_object_object_get_ex(parsed_json, "content", &content)) {

		//
                ///
                nd_log (NDLOG_ERR, "Failed to extract the \'content\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

	if (rCode != 200)	{
		
		if (!json_object_object_get_ex(content, "message", &ret_message))
		{

			//
                	///
                	nd_log (NDLOG_ERR, "response status code is not 200.- Failed to extract the \'message\' value from json.");

			json_object_put(parsed_json);
			return EXCEPTION;
		}

		if (!json_object_object_get_ex(content, "errorCode", &errorCode))
		{
			
			//
			///
			nd_log (LOG_ERR, "response status code is not 200.- Failed to extract the \'errorCode\' value from json.");
                        json_object_put(parsed_json);
                        return EXCEPTION;
		}

		const char *message_str = json_object_get_string(ret_message);
		const char *error_str = json_object_get_string(errorCode);

		if (message_str) {
            		plogin_result->message = strdup(message_str);
            		if (!plogin_result->message) {

				//
				///
				nd_log (NDLOG_ERR, "Memory allocation failed for message.");
				
                		json_object_put(parsed_json);
                		return EXCEPTION;
            		}
        	}

		if (error_str) {
            		plogin_result->errorcode = strdup(error_str);
            		if (!plogin_result->errorcode) {

				//
				///
				nd_log (NDLOG_ERR, "Memory allocation failed for error code.");
                		json_object_put(parsed_json);
                		return EXCEPTION;
            		}
        	}

		//
		///
		nd_log (NDLOG_ERR, "parse_JsonResponse_from_login_request  operation failed.- Error code: [%s]", plogin_result->errorcode);
        	json_object_put(parsed_json);
        	return EXCEPTION;
	}

	// Extract additional fields safely
    	const char *loginResult = "";
    	const char *userIdStr = "";
    	const char *userNumberStr = "";
    	const char *temporaryAccessKeyStr = "";
	const char *contentSimpleTypeStr = "";
	const char *stateStr = "";

	if (json_object_object_get_ex(content, PAM_JSON_KEY_NM_CONTENTSIMPLETYPE, &contentSimpleType))	{
		contentSimpleTypeStr = json_object_get_string(contentSimpleType);

		if (strcmp (contentSimpleTypeStr, PAM_JSON_KEY_VALUE_RET_SUCCESS) == 0 )
		{

		}

		else if (strcmp (contentSimpleTypeStr, PAM_JSON_KEY_VALUE_RET_REQREG) == 0 ) // need to registry message
		{

		}
		
		/*
		else if (strcmp (contentSimpletypeStr, PAM_JSON_KEY_VALUE_RET_FAILED) == 0 ) // auth failed // result code 400
		{

		}
		*/
	}

	if (json_object_object_get_ex(content, "state", &state))	{
		stateStr = json_object_get_string(state);

		if (strcmp (state, "failover") == 0 ) //failover = 2
		{

		}
		else // None = 1, passbyoption = 1
		{
		
		}
	}
	
	if (json_object_object_get_ex(content, "loginResult", &hi_loginResult)) {
		loginResult = json_object_get_string(hi_loginResult);
	}
	snprintf(plogin_result->loginResult, sizeof(plogin_result->loginResult), "%s", loginResult);

	if (json_object_object_get_ex(content, "temporaryAccessKey", &temporaryAccessKey)) {
                temporaryAccessKeyStr = json_object_get_string(temporaryAccessKey);
        }
        snprintf(plogin_result->temporaryAccessKey, sizeof(plogin_result->temporaryAccessKey), "%s", temporaryAccessKeyStr);
	
	/*
	if (json_object_object_get_ex(content, "userId", &userId)) {
		userIdStr = json_object_get_string(userId);
	}
	snprintf(plogin_result->userId, sizeof(plogin_result->userId), "%s", userIdStr);

	if (json_object_object_get_ex(content, "userNumber", &userNumber)) {
		userNumberStr = json_object_get_string(userNumber);
	}
	snprintf(plogin_result->userNumber, sizeof(plogin_result->userNumber), "%s", userNumberStr);
	*/

	// Handle boolean loginResult if temporaryAccessKey is empty
	if (strlen(plogin_result->temporaryAccessKey) == 0) {
		if (json_object_object_get_ex(content, "loginResult", &bool_result)) {
		    	snprintf(plogin_result->loginResult, sizeof(plogin_result->loginResult),
			     "%s", json_object_get_boolean(bool_result) ? "true" : "false");

			if (json_object_get_boolean(bool_result) == true )
			{
				if (json_object_object_get_ex(content, "userId", &userId)) {
					userIdStr = json_object_get_string(userId);
				}
				snprintf(plogin_result->userId, sizeof(plogin_result->userId), "%s", userIdStr);

				if (json_object_object_get_ex(content, "userNumber", &userNumber)) {
					userNumberStr = json_object_get_string(userNumber);
				}
				snprintf(plogin_result->userNumber, sizeof(plogin_result->userNumber), "%s", userNumberStr);
			}
		} else {

			//
			///
			nd_log (NDLOG_ERR, "parse_JsonResponse_from_login_request  operation failed.- loginResult not found");
		    	json_object_put(parsed_json);
		    	return EXCEPTION;
		}
	}

        // free memory
        json_object_put(parsed_json);
        return 0;
}

char *int_to_str_and_dup(int value) {
    char buffer[32]; // Temporary buffer to hold the string
    snprintf(buffer, sizeof(buffer), "%d", value);
    return strdup(buffer); // Duplicate the string
}


int parse_JsonResponse_from_twofact_otp_request(const char* res_doc, st_hiauth_twofact_login_result * plogin_result)         {

	struct json_object *parsed_json = NULL, *resultCode = NULL, *content = NULL, *bool_result = NULL,
                       *ret_message = NULL, *errorCode = NULL, *hi_loginResult = NULL,
                       *userId = NULL, *userNumber = NULL, *events = NULL;


	if (res_doc == NULL || plogin_result == NULL) {
		
		//
		///
		nd_log (NDLOG_ERR, "Invalid input parameters.");
        	return EXCEPTION;
    	}

	//
        ///
        nd_log (NDLOG_TRC, "====================================================================");
        nd_log (NDLOG_TRC, "[parse_JsonResponse_from_twofact_otp_request::res_doc information]");
        nd_log (NDLOG_TRC, " >> res_doc : %s", res_doc);
        nd_log (NDLOG_TRC, "--------------------------------------------------------------------");

        parsed_json = json_tokener_parse(res_doc);
        if (parsed_json == NULL) {

		//
		///
		nd_log (NDLOG_ERR, "Failed to parse json response.");

                return EXCEPTION;
        }

        // resultCode 추출
        if (!json_object_object_get_ex(parsed_json, "resultCode", &resultCode)) {

		//
                ///
                nd_log (NDLOG_ERR, "Failed to extract the \'resultCode\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        int rCode = json_object_get_int(resultCode);
        plogin_result->resultCode = rCode;

	// content 추출
        if (!json_object_object_get_ex(parsed_json, "content", &content)) {

		//
                ///
                nd_log (NDLOG_ERR, "Failed to extract the \'content\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

	if (rCode != 200)       {

		const char *message_str = "";
        	const char *error_str = "";
                if (json_object_object_get_ex(content, "message", &ret_message))
                {
			message_str = json_object_get_string(ret_message);
                }

		if (json_object_object_get_ex(content, "errorCode", &errorCode))
                {
			error_str = json_object_get_string(errorCode);
                }

		plogin_result->message = strdup(message_str);
        	plogin_result->errorcode = strdup(error_str);
        	json_object_put(parsed_json);

		//
                ///
                nd_log (NDLOG_ERR, "parse_JsonResponse_from_twofact_otp_request  operation failed.- Error code: [%s]", plogin_result->errorcode);

        	return EXCEPTION;
        }

	// Extract additional fields safely
    	const char *loginResult = "";
    	const char *userIdStr = "";
    	const char *userNumberStr = "";

	if (json_object_object_get_ex(content, "loginResult", &hi_loginResult)) {
		loginResult = json_object_get_string(hi_loginResult);
	}
	snprintf(plogin_result->loginResult, sizeof(plogin_result->loginResult), "%s", loginResult);

	if (json_object_object_get_ex(content, "userId", &userId)) {
		userIdStr = json_object_get_string(userId);
	}
	snprintf(plogin_result->userId, sizeof(plogin_result->userId), "%s", userIdStr);

	if (json_object_object_get_ex(content, "userNumber", &userNumber)) {
		userNumberStr = json_object_get_string(userNumber);
	}
	snprintf(plogin_result->userNumber, sizeof(plogin_result->userNumber), "%s", userNumberStr);

	// Extract events array
    	if (json_object_object_get_ex(content, "events", &events) &&
        	json_object_get_type(events) == json_type_array) 	{
		int array_len = json_object_array_length(events);

		for (int i = 0; i < array_len ; i ++ )
		{
			struct json_object *event = json_object_array_get_idx(events, i);
			struct json_object *stepNumber = NULL, *chosenFactor = NULL, *failover = NULL, *stateName = NULL, *code = NULL;

			const char *certStepSeqNo = "";
            		const char *certAppTpCode = "";
            		const char *certSucesFailYn = "";
            		const char *certTpCode = "";

			if (json_object_object_get_ex(event, "stepNumber", &stepNumber)) {
				certStepSeqNo = json_object_get_string(stepNumber);
			}
			plogin_result->certStepSeqNo = strdup(certStepSeqNo);

			if (json_object_object_get_ex(event, "failover", &failover)) {
				certAppTpCode = strcmp(json_object_get_string(failover), "false") == 0 ? "0" : "1";
			}
			plogin_result->certAppTpCode = strdup(certAppTpCode);

			if (json_object_object_get_ex(event, "stateName", &stateName)) {
				certSucesFailYn = strcmp(json_object_get_string(stateName), "Succeed") == 0 ? "1" : "0";
			}
			plogin_result->certSucesFailYn = strdup(certSucesFailYn);

			if (json_object_object_get_ex(event, "chosenFactor", &chosenFactor) &&
				json_object_object_get_ex(chosenFactor, "code", &code)) {
				certTpCode = json_object_get_string(code);
			}
			plogin_result->certTpCode = strdup(certTpCode);
		}
	}

	// free memory
        json_object_put(parsed_json);
        return 0;
}

/*
	//
*/
int parse_JsonResponse_from_ramdom_request(const char *json_str, Worker *worker)        {

        struct json_object *parsed_json;
        struct json_object *resultCode_obj;
        struct json_object *content_obj;
        struct json_object *issueKey_obj;
        struct json_object *randomKey_obj;

        // Parse the JSON response
        parsed_json = json_tokener_parse(json_str);
        if (parsed_json == NULL) {

		//
                ///
                nd_log (NDLOG_ERR, "Failed to parse json response.");

                return EXCEPTION;
        }

        // Get resultCode from the JSON
        if (!json_object_object_get_ex(parsed_json, "resultCode", &resultCode_obj)) {

		//
                ///
                nd_log (NDLOG_ERR, "Failed to get resultCode from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        int resultCode = json_object_get_int(resultCode_obj);
        if (resultCode != 200) {
                json_object_put(parsed_json);

		//
                ///
                nd_log (NDLOG_ERR, "Failed getRandomKey. resultCode = %d", resultCode);

                return EXCEPTION;
        }

        // Get content object
        if (!json_object_object_get_ex(parsed_json, "content", &content_obj)) {

		//
                ///
                nd_log (NDLOG_ERR, "Failed to extract the \'content\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        // Get issueKey from the content object
        if (!json_object_object_get_ex(content_obj, "issueKey", &issueKey_obj)) {

		//
                ///
                nd_log (NDLOG_ERR, "Cannot find issueKey in \'content\'object.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        const char *issueKey = json_object_get_string(issueKey_obj);
        if (strcmp(issueKey, "NULL") == 0) {

		//
                ///
                nd_log (NDLOG_ERR, "Cannot get issueKey in \'content\'object.- issueKey is null");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        // Get randomKey from the content object
        if (!json_object_object_get_ex(content_obj, "randomKey", &randomKey_obj)) {

		//
		///
		nd_log (NDLOG_ERR, "Cannot find randomKey in \'content\'object.");
                json_object_put(parsed_json);
                return EXCEPTION;
        }

        const char *randomKey = json_object_get_string(randomKey_obj);
        if (strcmp(randomKey, "NULL") == 0) {

		//
		///
		nd_log (NDLOG_ERR, "Cannot get randomKey in \'randomKey\'object.- randomKey is null");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        // Set issueKey and randomKey in the worker
        setIssueKey_to_struct(worker, issueKey);
        setRandomKey_to_struct(worker, randomKey);

        // Clean up
        json_object_put(parsed_json);
        return RET_SUCCESS;
}

/*
	//
*/
int requestOSAuthToApiServer (const char *username, const char * password, struct st_hiauth_os_login_result *result)
{
	return HI_AUTH_RET_SUCCEED;
}

/*
	//
*/
int requestHiwareAuthToApiServer (const char *username, const char *passwd, const char *agt_auth_no , struct st_hiauth_hiware_login_result *result)
{
	int retval = 0;
	Worker  worker;
        ApiHttpRes response;
        st_user_login_result log_result;

	//
	///
	nd_log (NDLOG_TRC, "[START Request Hiware Auth to Api Server >>]");

	response.m_data = malloc(1); // initialize
        response.m_data[0] = '\0';
        response.size = 0;

	if (username == NULL || passwd == NULL ||
                strlen (username) <= 0 || strlen (passwd) <= 0)         {
                free(response.m_data);

		//
		///
		nd_log (NDLOG_ERR, "input parameters are invalid.");
                return -1;
        }

	//
	///
	nd_log (NDLOG_TRC, " [#1 - Request Randomkey]");

	retval = getRandomKey_Request(&worker);
        if (retval != 0)                {
                //free (response.m_data);

		//
		///
		nd_log (NDLOG_ERR, "getRandomKey_Request function call failed.");

                return -1;
        }

	//GetUserLoginURL

	nd_log (NDLOG_TRC, " [#2 - User password encryption]");
	char * encPwd = encPassword(passwd, worker.randomKey);

	// create JSON object
        struct json_object *root = json_object_new_object();
        if (!root)              {
                free (encPwd);
                free (response.m_data);

		//
		///
		nd_log (NDLOG_ERR, "Failed to create a new JSON object in \'json_object_new_object()\'.");

                return -1;
        }

	char local_ip[INET_ADDRSTRLEN];
        get_local_ip(local_ip, sizeof(local_ip));

	char * strConfLocalIp  = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF,     "PAM_LOCAL_IP");

        // add data to  JSON object
        json_object_object_add(root, "issueKey",        json_object_new_string(worker.issueKey));
        json_object_object_add(root, "userId",          json_object_new_string(username));
        json_object_object_add(root, "password",        json_object_new_string(encPwd));
	json_object_object_add(root, "authorityId", 	json_object_new_string(agt_auth_no));
	if (strConfLocalIp)
		json_object_object_add(root, "ipAddress",       json_object_new_string(strConfLocalIp));
	else
		json_object_object_add(root, "ipAddress",       json_object_new_string(local_ip));
	/*
	json_object_object_add(root, "ipAddress",       json_object_new_string("192.168.14.15"));
	*/
	// convert to JSON string
        const char* sData = json_object_to_json_string(root);
        if (sData == NULL) {

		//
		///
		nd_log (NDLOG_ERR, "Failed to convert JSON object to string in \'json_object_to_json_string()\'.");

                json_object_put(root);  // free memory
                free (encPwd);
                free (response.m_data);
                return -1;  // except
        }

	//nd_log (NDLOG_TRC, "requestHiwareAuthToApiServer send data (%s)", sData);

	//
	///
	nd_log (NDLOG_TRC, " [#3 - Send authentication request data to the API server]");
	nd_log (NDLOG_TRC, "====================================================================");
	nd_log (NDLOG_TRC, " Data sent to the API server.");
	nd_log (NDLOG_TRC, "--------------------------------------------------------------------");
	nd_log (NDLOG_TRC, " %s",sData);
	nd_log (NDLOG_TRC, "--------------------------------------------------------------------");


	

	retval = SendPostDataWithDefaults (sData, &response, GetUserLoginURL());
        if (retval && strlen (response.m_data) > 0)             {

                retval = parse_JsonResponse_from_login_request(response.m_data, &log_result);
                if (retval != 0 )               {

			//
			///
			nd_log (NDLOG_ERR, "Failed to parse JSON response from login request in \'parse_JsonResponse_from_login_request()\'.");

			result->ret = log_result.resultCode; //strdup (log_result.resultCode);
			result->message = strdup (log_result.message);			
			result->errorcode = strdup (log_result.errorcode);

                        json_object_put(root);
                        free (encPwd);
                        free (response.m_data);
                        return -1;
                }


		result->ret = log_result.resultCode;
		setUserLoginResult (log_result.loginResult);
		setTemporaryAccessKey (log_result.temporaryAccessKey);
		setHiwareUserNumber(log_result.userNumber);

        }

        json_object_put (root );
        free (encPwd);
        free (response.m_data);

	return HI_AUTH_RET_SUCCEED;
}

/*
	//
*/
int requestTwoFactAuthToApiserver (const char *type, const char *temporaryAccessKey, const char * stepNumber, const char *authCode, const char* langCode, st_hiauth_twofact_login_result *result )
{
	int retval = 0;
	st_hiauth_twofact_login_result log_result;
        //Worker  worker;
        ApiHttpRes response;

	response.m_data = malloc(1); // initialize
        response.m_data[0] = '\0';
        response.size = 0;

	struct json_object *root = json_object_new_object();
        if (!root)              {

		//
		///
		nd_log (NDLOG_ERR, "Failed to create a new JSON object using \'json_object_new_object()\'.");
		
                free (response.m_data);
                return -1;
        }

	// add data to  JSON object
        json_object_object_add(root, "type",        			json_object_new_string(type));
        json_object_object_add(root, "temporaryAccessKey",          	json_object_new_string(temporaryAccessKey));
        json_object_object_add(root, "stepNumber",        		json_object_new_string(stepNumber));

	struct json_object *parameters = json_object_new_object();
    	if (!parameters) 	{

		//
		///
		nd_log (NDLOG_ERR, "Failed to create a new JSON object for \'parameters\' using \'json_object_new_object()\'.");

        	json_object_put(root);
        	free(response.m_data);
        	return -1;
    	}

	json_object_object_add(parameters, "authCode", json_object_new_string(authCode));

	// Add the "parameters" object to the root
    	json_object_object_add(root, "parameters", parameters);
	
	// Add "langCode" to the root JSON object
    	json_object_object_add(root, "langCode", json_object_new_string(langCode));


	 // convert to JSON string
        const char* sData = json_object_to_json_string(root);
        if (sData == NULL) {

		//
		///
		nd_log (NDLOG_ERR, "Failed to convert JSON object \'root\' to string - \'json_object_to_json_string()\' returned NULL.");

                json_object_put(root);  // free memory
                free (response.m_data);
                return -1;  // except
        }

	//
	///
	nd_log (NDLOG_TRC, "[request mfa data]");
	nd_log (NDLOG_TRC, " * request url : %s", GetTwoFact_OtpURL());
	nd_log (NDLOG_TRC, " * data :%s", sData);

	retval = SendPostDataWithDefaults (sData, &response, GetTwoFact_OtpURL());
        if (retval && strlen (response.m_data) > 0)             {

                retval = parse_JsonResponse_from_twofact_otp_request(response.m_data, &log_result);

                if (retval != 0 )               {

			//
			///
			nd_log (NDLOG_ERR, "Failed to parse JSON response from two-factor OTP request in \'parse_JsonResponse_from_twofact_otp_request()\' - Return value is non-zero.");


                        result-> resultCode= log_result.resultCode; //strdup (log_result.resultCode);
                        result->message = strdup (log_result.message);
                        result->errorcode = strdup (log_result.errorcode);

                        json_object_put(root);
                        free (response.m_data);
                        return -1;
                }

                result->resultCode = log_result.resultCode;
                setUserLoginResult (log_result.loginResult);
                setTemporaryAccessKey (log_result.temporaryAccessKey);
		setHiwareUserNumber(log_result.userNumber);

		result->certTpCode = strdup( log_result.certTpCode);
		result->certAppTpCode = strdup (log_result.certAppTpCode);
		result->certSucesFailYn = strdup( log_result.certSucesFailYn);
		result->certStepSeqNo = strdup( log_result.certStepSeqNo); 
        }

        json_object_put (root );
        free (response.m_data);


	return HI_AUTH_RET_SUCCEED;
}

/*
        //st_hiauth_su_login_result
*/
int requestSuAuthToApiServer (const char *username, const char * password, struct st_hiauth_su_login_result *result)
{
	return HI_AUTH_RET_SUCCEED;
}

/*
	//
*/
int requestSuAccessPermissionsToApiServer (const char *current_user, const char * switch_user, struct st_hiauth_su_access_perm_result * result )
{
	return HI_AUTH_RET_SUCCEED;
}

