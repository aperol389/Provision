

#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#define CA_FILE "CA.pem"
#define CLIENT_CERT_FILE "client.pem"
#define CLIENT_CERT_TYPE "PEM"
#define CLIENT_KEY "clientKey.pem"
#define CLIENT_KEY_TYPE "PEM"
#define CLIENT_KEY_PASSWORD "1234"

int main(int argc, char **argv)
{
    curl_global_init(CURL_GLOBAL_ALL);

    CURL *pCurl = curl_easy_init();

    if (NULL != pCurl)
    {
        printf("curl_easy_init() success.\n");

        curl_easy_setopt(pCurl, CURLOPT_URL, "https://eed2.com/");

        curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, 8);

        // 验证证书的有效性
        curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 1);

        // 验证证书中的主机名(Common Name)和访问的主机是否一致
        curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 1);

        // 指定信任的根证书
        curl_easy_setopt(pCurl, CURLOPT_CAINFO, CA_FILE);

        bool clientAuthentication = true;

        // 是否进行双向认证
        if (clientAuthentication)
        {
            // 指定客户端证书
            curl_easy_setopt(pCurl, CURLOPT_SSLCERT, CLIENT_CERT_FILE);

            // 客户端证书类型，用于双向认证
            // curl_easy_setopt(pCurl, CURLOPT_SSLCERTTYPE, CLIENT_CERT_TYPE);

            // 客户端私钥，用于双向认证
            curl_easy_setopt(pCurl, CURLOPT_SSLKEY, CLIENT_KEY);

            // 客户端私钥类型，用于双向认证
            // curl_easy_setopt(pCurl, CURLOPT_SSLKEYTYPE, CLIENT_KEY_TYPE);

            // 客户端私钥密码，用于双向认证
            // curl_easy_setopt(pCurl, CURLOPT_KEYPASSWD, CLIENT_KEY_PASSWORD);
        }

        CURLcode res = curl_easy_perform(pCurl);

        if (res != CURLE_OK)
        {
            printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else
        {
            printf("curl_easy_perform() success.\n");
        }

        curl_easy_cleanup(pCurl);
    }
    else
    {
        printf("curl_easy_init() failed.\n");
    }

    return 0;
}