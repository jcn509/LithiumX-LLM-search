#include <nxdk/net.h>
#include <stdio.h>
#include <string.h>
#include <xboxkrnl/xboxkrnl.h>
#include <lwip/apps/http_client.h>

#include <hal/debug.h>
#include <hal/video.h>

err_t my_http_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	debugPrint("tcp_recv_fn:\n");
	for(uint16_t i=0;i<p->len;i++)
		debugPrint("%c", ((char*) p->payload)[i]);
	debugPrint("\n");
	return ERR_OK;
}
 
void my_httpc_result_fn(void *arg, httpc_result_t httpc_result, u32_t rx_content_len, u32_t srv_res, err_t err)
{
    debugPrintNum(httpc_result);
	debugPrint("my_httpc_result_fn (DNS) %d %ld %ld\n", httpc_result, rx_content_len, srv_res);
        // if the download succeeds srv_res should be 200, httpc_result 0 (HTTPC_RESULT_OK) and rx_content_len!=0
}


err_t my_httpc_headers_done_fn(httpc_state_t *connection, void *arg, struct pbuf *hdr, u16_t hdr_len, u32_t content_len) {
    debugPrint("my_httpc_headers_done_fn %ld\n", content_len);
    return ERR_OK;
}

httpc_connection_t http_settings;
httpc_state_t *connection;
void try_http_conn(void* arg)
{
	// ip4_addr_t host;
    // IP4_ADDR(&host, 54, 209, 95, 91);
    
	http_settings.use_proxy =0;
	http_settings.headers_done_fn = my_httpc_headers_done_fn;
	http_settings.result_fn = my_httpc_result_fn;

    //httpc_get_file(&host, 80, "/", &http_settings, my_http_cb, 0, &connection);

    httpc_get_file_dns("httpbin.org", 80, "/", &http_settings, my_http_cb, 0, &connection);
}


// void net_cleanup(void) {
//     nxNetShutdown();
// }

int main(void) {
    XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);
    int net_init = nxNetInit(NULL);
    if (net_init != 0) {
        debugPrint("Failed to intialise net %i\n", net_init);
        while (1) NtYieldExecution();
    }

    debugPrint("Hello nxdk HTTP with DNS!\n");
    sys_thread_new("http_client_netconn", try_http_conn, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);

    // const char *url = "http://example.com";
    // make_http_request(url);

    //net_cleanup();

    while (1) {
        NtYieldExecution();
    }
    return 0;
}