#define _CRT_RAND_S

#include <stdarg.h>
#include <string.h>

#include <hal/debug.h>
#include <hal/video.h>
#include <nxdk/net.h>

#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>

#include "gemini_api_key.h"


/* Replace with your server's CA certificate */
static const char ca_cert[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw\n"
"CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU\n"
"MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw\n"
"MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp\n"
"Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA\n"
"A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo\n"
"27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w\n"
"Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw\n"
"TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl\n"
"qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH\n"
"szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8\n"
"Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk\n"
"MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92\n"
"wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p\n"
"aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN\n"
"VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID\n"
"AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E\n"
"FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb\n"
"C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe\n"
"QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy\n"
"h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4\n"
"7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J\n"
"ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef\n"
"MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/\n"
"Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT\n"
"6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ\n"
"0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm\n"
"2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb\n"
"bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c\n"
"-----END CERTIFICATE-----\n";

// BEGIN: Glue code provided by Thrimbor
int custom_mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )
{
    int fd = ((mbedtls_net_context *) ctx)->fd;
    return send(fd, buf, len, 0);
}

int custom_mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len )
{
    int fd = ((mbedtls_net_context *) ctx)->fd;
    int r = recv(fd, buf, len, 0);
    if (r == -1) debugPrint("failed, errno: %d\n", errno);
    return r;
}

int custom_mbedtls_net_connect( mbedtls_net_context *ctx, const char *host,
                         const char *port, int proto )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    struct addrinfo hints, *addr_list, *cur;

    /* Do name resolution with IPv4 */
    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_INET;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if( getaddrinfo( host, port, &hints, &addr_list ) != 0 )
        return( MBEDTLS_ERR_NET_UNKNOWN_HOST );

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for( cur = addr_list; cur != NULL; cur = cur->ai_next )
    {
        ctx->fd = (int) socket( cur->ai_family, cur->ai_socktype,
                            cur->ai_protocol );
        if( ctx->fd < 0 )
        {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if( connect( ctx->fd, cur->ai_addr, cur->ai_addrlen ) == 0 )
        {
            ret = 0;
            break;
        }

        close( ctx->fd );
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo( addr_list );

    return( ret );
}

static inline size_t min (size_t a, size_t b)
{
    return (a < b) ? a : b;
}

int mbedtls_hardware_poll (void *data, unsigned char *output, size_t len, size_t *olen) {
    size_t written = 0;
    while (written < len) {
        uint32_t buf;
        rand_s(&buf);
        size_t bytes_to_copy = min(len-written, 4);
        memcpy(output, &buf, bytes_to_copy);
        output += bytes_to_copy;
        written += bytes_to_copy;
    }

    *olen = written;
    return 0;
}
// END: Glue code provided by Thrimbor

static size_t num_chars_to_escape(const char* const string) {
    size_t num_chars_to_escape = 0;
    const char* const to_escape = "\"\n\r\t";
    for(const char* current_char = string; *current_char != '\0'; current_char++) {
        for(const char* char_needs_escaping = to_escape; *char_needs_escaping != '\0'; char_needs_escaping++) {
            if(*current_char == *char_needs_escaping) {
                num_chars_to_escape++;
                break;
            }
        }
    }
    return num_chars_to_escape;
}

void make_gemini_request(const char* const prompt) {

    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;

    const char *host = "generativelanguage.googleapis.com";
    const char *port = "443";

    // TODO: add example JSON
    const char prompt_json_begin[] = "{\"contents\": [{\"parts\":[{\"text\": \"";
    const char prompt_json_end[] = "\"}]}]}";

    const size_t total_json_size = (sizeof(prompt_json_begin) -1) + strlen(prompt) + (sizeof(prompt_json_end) -1);
    // Currently making the dangerous assumption that the prompt contains no characters
    // that need to be escaped...

    char request[1000];
    char error_buf[100];
    int ret;
    sprintf(
        request,
        "POST /v1beta/models/gemini-1.5-flash:generateContent?key=%s"                      
        " HTTP/1.1\r\n" 
        "Host: %s\r\n" 
        "Connection: close\r\n"
        "Accept: */*\r\n" 
        "User-Agent: Mozilla/4.0 (compatible; esp8266 Lua; Windows NT 5.1)\r\n" 
        "Content-Type: application/json\r\n"
        "Content-Length: %i\r\n"
        "\r\n"
        "%s%s%s"
        "\r\n",
        GEMINI_API_KEY, host, total_json_size, prompt_json_begin, prompt, prompt_json_end);



    // Initialize structures
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);

    // Seed the RNG
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("Failed to seed RNG: %s\n", error_buf);
        goto exit;
    }

    // Configure SSL defaults
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("SSL config defaults failed: %s\n", error_buf);
        goto exit;
    }

    mbedtls_x509_crt_parse(&cacert, (const unsigned char *)ca_cert, sizeof(ca_cert));
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    // Insecure option for testing (disable certificate verification)
    //mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Connect to server using custom function
    if ((ret = custom_mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("Connection failed: %s\n", error_buf);
        goto exit;
    }

    // Setup SSL context
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("SSL setup failed: %s\n", error_buf);
        goto exit;
    }

    // Set hostname for SNI
    if ((ret = mbedtls_ssl_set_hostname(&ssl, host)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("Hostname set failed: %s\n", error_buf);
        goto exit;
    }

    // Set custom BIO callbacks
    mbedtls_ssl_set_bio(&ssl, &server_fd, custom_mbedtls_net_send, custom_mbedtls_net_recv, NULL);

    // Perform SSL handshake
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, error_buf, sizeof(error_buf));
            debugPrint("Handshake failed: %s\n", error_buf);
            goto exit;
        }
    }

    // Verify server certificate (if verification enabled)
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        debugPrint("Certificate verification failed (Flags: 0x%X)\n", flags);
        goto exit;
    }

    // Send HTTP request
    size_t written = 0;
    size_t request_len = strlen(request);
    while (written < request_len) {
        ret = mbedtls_ssl_write(&ssl, (const unsigned char*)request + written, request_len - written);
        if (ret <= 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            mbedtls_strerror(ret, error_buf, sizeof(error_buf));
            debugPrint("Write failed: %s\n", error_buf);
            goto exit;
        }
        written += ret;
    }

    // Read response
    unsigned char buf[128];
    do {
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret <= 0) break;

        buf[ret] = '\0';
        debugPrint("%s", buf);
        Sleep(1000);
    } while (1);

    if (ret < 0 && ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        debugPrint("Read failed: %s\n", error_buf);
    }

exit:
    // Cleanup
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&cacert);
}

void try_https_request(void* arg) {
    make_gemini_request("Explain how AI works");
} 

int main(void) {
    // Note: using widescreen mode here because otherwise the content
    // won't quite fit on the screen when using debugPrint...
    XVideoSetMode(720, 480, 32, REFRESH_DEFAULT);
    int net_init = nxNetInit(NULL);
    if (net_init != 0) {
        debugPrint("Failed to intialise net %i\n", net_init);
        while (1) NtYieldExecution();
    }

    debugPrint("NXDK HTTPS test!\n");
    sys_thread_new("https_client_netconn", try_https_request, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);

    while (1) {
        NtYieldExecution();
    }
    return 0;
}