/*
 * COMP 321 Project 6: Web Proxy
 *
 * This program implements a multithreaded HTTP proxy.
 *
 * John Talghader jat8, Anjali Yamasani ay50
 */

#include <assert.h>

#include "csapp.h"

static void client_error(int fd, const char *cause, int err_num,
    const char *short_msg, const char *long_msg);
static char *create_log_entry(const struct sockaddr_in *sockaddr,
    const char *uri, int size);
static int parse_uri(const char *uri, char **hostnamep, char **portp,
    char **pathnamep);

static void proxy_doit(int connfd, struct sockaddr_storage clientaddr);
static void forward_request(int clientfd, int connfd, char *request, struct sockaddr_storage clientaddr);
static void log_entry(struct sockaddr_in *sockaddr, char *uri, size_t size);
static int build_request(rio_t * rio, int connfd, char **request);

int counter = 0;
FILE *proxy_log = NULL;

/*
 * Requires:
 *   <to be filled in by the student(s)>
 *
 * Effects:
 *   <to be filled in by the student(s)>
 */
int
main(int argc, char **argv)
{
	int listenfd, connfd;
	char *ip_addr = NULL;
	socklen_t clientlen;
	struct sockaddr_storage clientaddr; /* Enough space for any address */
	char client_hostname[MAXLINE], client_port[MAXLINE];

	if (argc != 2) {
		fprintf(stderr, "usage: %s <port number>\n", argv[0]);
		exit(0);
	}

	// Open a listening socket
	listenfd = Open_listenfd(argv[1]);

	// Open proxy.log file
	proxy_log = fopen("proxy.log", "a"); // Open log file in append mode
	if (proxy_log == NULL) {
		perror("Error opening proxy.log");
		exit(EXIT_FAILURE);
	}

	// Iterate through all clients trying to connect to proxy
	while (1) {
		// Accept incoming client connection
		struct hostent *host_addresses;
		struct in_addr **addr_list;
		clientlen = sizeof(struct sockaddr_storage);
		connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
		Getnameinfo((SA *)&clientaddr, clientlen, client_hostname,
		    MAXLINE, client_port, MAXLINE, 0);

		host_addresses = gethostbyname(client_hostname);
		if (host_addresses == NULL) {
			fprintf(stderr,
			    "gethostbyname: Unable to resolve hostname\n");
			exit(1);
		}

		addr_list = (struct in_addr **)host_addresses->h_addr_list;
		if (addr_list[0] != NULL) {
			ip_addr = inet_ntoa(*addr_list[0]);
			printf(
			    "\nRequest %d: Received request from client (%s)\n",
			    counter, ip_addr);
		} else {
			fprintf(stderr,
			    "No IP address found for the hostname\n");
			exit(1);
		}

		proxy_doit(connfd, clientaddr);
		counter++;
		Close(connfd);
	}

	fclose(proxy_log);
	exit(0);
}

/*
 * Requires:
 *   The parameter "uri" must point to a properly NUL-terminated string.
 *
 * Effects:
 *   Given a URI from an HTTP proxy GET request (i.e., a URL), extract the
 *   host name, port, and path name.  Create strings containing the host name,
 *   port, and path name, and return them through the parameters "hostnamep",
 *   "portp", "pathnamep", respectively.  (The caller must free the memory
 *   storing these strings.)  Return -1 if there are any problems and 0
 *   otherwise.
 */
static int
parse_uri(const char *uri, char **hostnamep, char **portp, char **pathnamep)
{
	const char *pathname_begin, *port_begin, *port_end;

	if (strncasecmp(uri, "http://", 7) != 0)
		return (-1);

	/* Extract the host name. */
	const char *host_begin = uri + 7;
	const char *host_end = strpbrk(host_begin, ":/ \r\n");
	if (host_end == NULL)
		host_end = host_begin + strlen(host_begin);
	int len = host_end - host_begin;
	char *hostname = Malloc(len + 1);
	strncpy(hostname, host_begin, len);
	hostname[len] = '\0';
	*hostnamep = hostname;

	/* Look for a port number.  If none is found, use port 80. */
	if (*host_end == ':') {
		port_begin = host_end + 1;
		port_end = strpbrk(port_begin, "/ \r\n");
		if (port_end == NULL)
			port_end = port_begin + strlen(port_begin);
		len = port_end - port_begin;
	} else {
		port_begin = "80";
		port_end = host_end;
		len = 2;
	}
	char *port = Malloc(len + 1);
	strncpy(port, port_begin, len);
	port[len] = '\0';
	*portp = port;

	/* Extract the path. */
	if (*port_end == '/') {
		pathname_begin = port_end;
		const char *pathname_end = strpbrk(pathname_begin, " \r\n");
		if (pathname_end == NULL)
			pathname_end = pathname_begin + strlen(pathname_begin);
		len = pathname_end - pathname_begin;
	} else {
		pathname_begin = "/";
		len = 1;
	}
	char *pathname = Malloc(len + 1);
	strncpy(pathname, pathname_begin, len);
	pathname[len] = '\0';
	*pathnamep = pathname;

	return (0);
}

/*
 * Requires:
 *   The parameter "sockaddr" must point to a valid sockaddr_in structure.  The
 *   parameter "uri" must point to a properly NUL-terminated string.
 *
 * Effects:
 *   Returns a string containing a properly formatted log entry.  This log
 *   entry is based upon the socket address of the requesting client
 *   ("sockaddr"), the URI from the request ("uri"), and the size in bytes of
 *   the response from the server ("size").
 */
static char *
create_log_entry(const struct sockaddr_in *sockaddr, const char *uri, int size)
{
	struct tm result;

	/*
	 * Create a large enough array of characters to store a log entry.
	 * Although the length of the URI can exceed MAXLINE, the combined
	 * lengths of the other fields and separators cannot.
	 */
	const size_t log_maxlen = MAXLINE + strlen(uri);
	char *const log_str = Malloc(log_maxlen + 1);

	/* Get a formatted time string. */
	time_t now = time(NULL);
	int log_strlen = strftime(log_str, MAXLINE,
	    "%a %d %b %Y %H:%M:%S %Z: ", localtime_r(&now, &result));

	/*
	 * Convert the IP address in network byte order to dotted decimal
	 * form.
	 */
	Inet_ntop(AF_INET, &sockaddr->sin_addr, &log_str[log_strlen],
	    INET_ADDRSTRLEN);
	log_strlen += strlen(&log_str[log_strlen]);

	/*
	 * Assert that the time and IP address fields occupy less than half of
	 * the space that is reserved for the non-URI fields.
	 */
	assert(log_strlen < MAXLINE / 2);

	/*
	 * Add the URI and response size onto the end of the log entry.
	 */
	snprintf(&log_str[log_strlen], log_maxlen - log_strlen, " %s %d", uri,
	    size);

	return (log_str);
}

/*
 * Requires:
 *   The parameter "fd" must be an open socket that is connected to the client.
 *   The parameters "cause", "short_msg", and "long_msg" must point to properly
 *   NUL-terminated strings that describe the reason why the HTTP transaction
 *   failed.  The string "short_msg" may not exceed 32 characters in length,
 *   and the string "long_msg" may not exceed 80 characters in length.
 *
 * Effects:
 *   Constructs an HTML page describing the reason why the HTTP transaction
 *   failed, and writes an HTTP/1.0 response containing that page as the
 *   content.  The cause appearing in the HTML page is truncated if the
 *   string "cause" exceeds 2048 characters in length.
 */
static void
client_error(int fd, const char *cause, int err_num, const char *short_msg,
    const char *long_msg)
{
	char body[MAXBUF], headers[MAXBUF], truncated_cause[2049];

	assert(strlen(short_msg) <= 32);
	assert(strlen(long_msg) <= 80);
	/* Ensure that "body" is much larger than "truncated_cause". */
	assert(sizeof(truncated_cause) < MAXBUF / 2);

	/*
	 * Create a truncated "cause" string so that the response body will not
	 * exceed MAXBUF.
	 */
	strncpy(truncated_cause, cause, sizeof(truncated_cause) - 1);
	truncated_cause[sizeof(truncated_cause) - 1] = '\0';

	/* Build the HTTP response body. */
	snprintf(body, MAXBUF,
	    "<html><title>Proxy Error</title><body bgcolor=\"ffffff\">\r\n"
	    "%d: %s\r\n"
	    "<p>%s: %s\r\n"
	    "<hr><em>The COMP 321 Web proxy</em>\r\n",
	    err_num, short_msg, long_msg, truncated_cause);

	/* Build the HTTP response headers. */
	snprintf(headers, MAXBUF,
	    "HTTP/1.0 %d %s\r\n"
	    "Content-type: text/html\r\n"
	    "Content-length: %d\r\n"
	    "\r\n",
	    err_num, short_msg, (int)strlen(body));

	/* Write the HTTP response. */
	if (rio_writen(fd, headers, strlen(headers)) != -1)
		rio_writen(fd, body, strlen(body));
}

// Prevent "unused function" and "unused variable" warnings.
static const void *dummy_ref[] = { client_error, create_log_entry, dummy_ref,
	parse_uri };

#include "csapp.h"

void print_string_with_special_chars(const char *str) {
    while (*str) {
        switch (*str) {
            case '\n':
                printf("\\n");
                break;
            case '\r':
                printf("\\r");
                break;
            case '\t':
                printf("\\t");
                break;
            // Add more cases for other special characters if needed
            default:
                if (*str < 32 || *str > 126) {
                    // Print non-printable characters using their ASCII code
                    printf("\\x%02X", (unsigned char)*str);
                } else {
                    // Print printable characters as is
                    putchar(*str);
                }
                break;
        }
        str++;
    }
}

static void
proxy_doit(int connfd, struct sockaddr_storage clientaddr)
{
	char *request;
	int serverfd;
	rio_t rio;

	request = malloc(1);
	rio_readinitb(&rio, connfd);
	serverfd = build_request(&rio, connfd, &request);
	// print_string_with_special_chars(request);
	forward_request(serverfd, connfd, request, clientaddr);

	free(request);
	Close(serverfd);
}

static void
forward_request(int serverfd, int connfd, char *request, struct sockaddr_storage clientaddr)
{
	char response[MAXLINE];
	char uri[MAXLINE];
	rio_t server_rio;
	rio_t client_rio;

	rio_readinitb(&client_rio, serverfd);
	rio_readlineb(&client_rio, uri, MAXLINE);

	// Print to stdout to match reference solution
	printf("%s\n", uri);
	printf("*** End of Request ***\n");
	printf("Request %d: Forwarding request to server:\n", counter);
	printf(request);

	// Write the request to the server
	rio_readinitb(&server_rio, serverfd);
	rio_writen(serverfd, request, strlen(request));

	size_t total_bytes = 0;
	size_t n;

	// Write response back to client
	while ((n = rio_readlineb(&server_rio, response, MAXLINE)) != 0) {
		total_bytes += n;
		rio_writen(connfd, response, n);
	}

	// Print to stdout to match reference solution
	printf("*** End of Request ***\n");
	printf("Request %d: Forwarded %ld bytes from server to client\n", counter, total_bytes);

	log_entry((struct sockaddr_in *)&clientaddr, uri, total_bytes);
}

static void
log_entry(struct sockaddr_in *sockaddr, char *uri, size_t size)
{
	char *entry;
	entry = create_log_entry(sockaddr, uri, size);

	fprintf(proxy_log, "%s\n", entry);
	free(entry);
	fflush(proxy_log);
}

static int
build_request(rio_t *rio_ptr, int connfd, char **request) {
	char method[MAXLINE], uri[MAXLINE], version[MAXLINE];
	char *hostname = NULL, *port = NULL, *pathname = NULL;
	char buf[MAXLINE];
	size_t request_size;
	int serverfd;

	rio_readlineb(rio_ptr, buf, MAXLINE);

	// Parse the request line
	if (sscanf(buf, "%s %s %s", method, uri, version) < 3) {
		client_error(connfd, method, 400, "Bad Request",
			"Proxy received a malformed request line");
		exit(EXIT_FAILURE);
	}

	// Check if method is GET or not
	if (strcasecmp(method, "GET") != 0) {
		client_error(connfd, method, 501, "Not implemented",
			"Proxy does not implement this method");
		exit(EXIT_FAILURE);
	}

	// Parse the URI
	if (parse_uri(uri, &hostname, &port, &pathname) == -1) {
		client_error(connfd, method, 400, "Bad Request",
			"Proxy could not parse the request URI");
		exit(EXIT_FAILURE);
	}
	
	request_size = strlen(method) + strlen(pathname) + strlen(version) + 5; // Add 4, two for space, two for carriage and endline character, one for null terminator
	*request = realloc(*request, request_size);
	strcpy(*request, method);
	strcat(*request, " ");
	strcat(*request, pathname);
	strcat(*request, " ");
	strcat(*request, version);
	strcat(*request, "\r\n");

	// Move to first request header
	rio_readlineb(rio_ptr, buf, MAXLINE);

	// Iterate until there are no more request headers
	while (strcmp(buf, "\r\n") != 0) {
		// Strip unwanted headers out of request
		if (strstr(buf, "Connection") == NULL && strstr(buf, "Keep-Alive") == NULL && strstr(buf, "Proxy-Connection") == NULL) {
			request_size += strlen(buf);
			*request = realloc(*request, request_size);
		}

		strcat(*request, buf);

		rio_readlineb(rio_ptr, buf, MAXLINE);
	}

	// Add "Connection: close" header to request
	request_size += strlen("Connection: close\r\n\r\n");
	*request = realloc(*request, request_size);
	strcat(*request, "Connection: close\r\n\r\n");

	serverfd = Open_clientfd(hostname, port);
	if (serverfd == -1) {
		fprintf(stderr, "Error: Error opening serverfd");
		exit(EXIT_FAILURE);
	}

	return serverfd;
}