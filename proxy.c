/*
 * COMP 321 Project 6: Web Proxy
 *
 * This program implements a multithreaded HTTP proxy.
 *
 * John Talghader jat8, Anjali Yamasani ay50
 */

#include <assert.h>

#include "csapp.h"
#define NTHREADS 4
#define SBUFSIZE 16

struct client_struct {
	struct sockaddr_storage clientaddr;
	int connfd;
};

struct sbuf {
	struct client_struct *client_buf;
	int numSlots;		       // max num slots
	int count;		       // num items in the buffer
	int front;		       // buf[(front+1)%n] is the first item
	int rear;		       // buf[rear%n] is the last item
	pthread_mutex_t mutex;	       // protects access to buf
	pthread_cond_t cond_not_empty; // signals that a get is possible
	pthread_cond_t cond_not_full;  // signals that a put is possible
};

static void client_error(int fd, const char *cause, int err_num,
    const char *short_msg, const char *long_msg);
static char *create_log_entry(const struct sockaddr_in *sockaddr,
    const char *uri, int size);
static int parse_uri(const char *uri, char **hostnamep, char **portp,
    char **pathnamep);

static void proxy_doit(int connfd, struct sockaddr_storage clientaddr);
static void forward_request(int clientfd, int connfd, char *request_line,
    char *request_header, struct sockaddr_storage clientaddr);
static void log_entry(struct sockaddr_in *sockaddr, char *uri, size_t size);
static void *thread(void *vargp);
static void sbuf_init(struct sbuf *sp, int n);
static void sbuf_insert(struct sbuf *sp, struct client_struct client);
static struct client_struct sbuf_remove(struct sbuf *sp);
static void sbuf_clean(struct sbuf *sp);

/* Global variables */
int counter = 0;
FILE *proxy_log = NULL;
struct sbuf sbuffer; /* Shared buffer of connected descriptors */
// char *http_request_flag; /* HTTP/1.0 or HTTP/1.1 */

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
	int listenfd;
	socklen_t clientlen;
	// struct sockaddr_storage clientaddr; /* Enough space for any address
	// */
	char client_hostname[MAXLINE], client_port[MAXLINE];
	pthread_t tid;
	// char *ip_addr = NULL;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <port number>\n", argv[0]);
		exit(0);
	}

	// ignore SIGPIPE signals
	Signal(SIGPIPE, SIG_IGN);

	// Open proxy.log file
	proxy_log = fopen("proxy.log", "a"); // Open log file in append mode
	if (proxy_log == NULL) {
		perror("Error opening proxy.log");
		exit(EXIT_FAILURE);
	}

	// Open a listening socket
	listenfd = Open_listenfd(argv[1]);

	// Initialize sbuffer object and its fields
	sbuf_init(&sbuffer, SBUFSIZE);
	printf("Successfully initialized sbuf.\n");

	// Creates worker threads
	for (int i = 0; i < NTHREADS; i++) {
		Pthread_create(&tid, NULL, thread, NULL);
	}

	// Iterate through all clients trying to connect to proxy
	while (1) {
		// Accept incoming client connection
		struct sockaddr_storage clientaddr;
		clientlen = sizeof(clientaddr);

		// struct hostent *host_addresses;
		// struct in_addr **addr_list;
		// Cast sockaddr_storage to sockaddr_in to access specific
		// fields if needed
		// struct sockaddr_in *clientaddr_in = (struct sockaddr_in
		// *)&clientaddr;

		// host_addresses = gethostbyname(client_hostname);
		// if (host_addresses == NULL) {
		// 	fprintf(stderr,
		// 	    "gethostbyname: Unable to resolve hostname\n");
		// 	exit(1);
		// }

		// addr_list = (struct in_addr **)host_addresses->h_addr_list;
		// if (addr_list[0] != NULL) {
		// 	ip_addr = inet_ntoa(*addr_list[0]);
		// 	printf(
		// 	    "\nRequest %d: Received request from client (%s)\n",
		// 	    counter, ip_addr);
		// } else {
		// 	fprintf(stderr,
		// 	    "No IP address found for the hostname\n");
		// 	exit(1);
		// }

		int connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);

		struct client_struct client;

		if (client.connfd < 0) {
			perror("Accept error");
			continue;
		}

		client.connfd = connfd;
		client.clientaddr = clientaddr;

		// Make sure you use the correct size for the specific address
		// family
		int res = getnameinfo((struct sockaddr *)&clientaddr, clientlen,
		    client_hostname, MAXLINE, client_port, MAXLINE,
		    NI_NUMERICHOST | NI_NUMERICSERV);

		if (res != 0) {
			fprintf(stderr, "Getnameinfo error: %s\n",
			    gai_strerror(res));
			// Handle error, for example, by continuing to the next
			// iteration of the loop.
			continue;
		}

		printf("\nRequest %d: Received request from client %s:%s\n",
		    counter, client_hostname, client_port);

		sbuf_insert(&sbuffer, client);
		// this proxy_doit might need to be moved
		// proxy_doit(connfd, clientaddr);
		counter++;
		// this close might need to be moved
		// Close(connfd);
	}

	Close(listenfd);
	fclose(proxy_log);
	sbuf_clean(&sbuffer);
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

static void
proxy_doit(int connfd, struct sockaddr_storage clientaddr)
{
	size_t n;
	int request_line_read = 0; // flag to indicate if the GET line was
	char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
	char *hostname = NULL, *port = NULL, *pathname = NULL;
	char request_line[MAXLINE];
	char request_header[MAXLINE];
	rio_t rio;
	int serverfd = -1;

	// http_request_flag = version;

	Rio_readinitb(&rio, connfd);

	while ((n = Rio_readlineb(&rio, buf, MAXLINE)) != 0) {
		if (strcmp(buf, "\r\n") == 0) {
			// Empty line found, exit the loop
			break;
		}

		if (!request_line_read) {
			strncpy(request_line, buf, MAXLINE);
			if (sscanf(buf, "%s %s %s", method, uri, version) < 3) {
				client_error(connfd, method, 400, "Bad Request",
				    "Proxy received a malformed request line");
				return;
			}

			if (strcasecmp(method, "GET") != 0) {
				client_error(connfd, method, 501,
				    "Not implemented",
				    "Proxy does not implement this method");
				return;
			}
			// verify 1.0 or 1.1
			if (strcasecmp(version, "HTTP/1.0") &&
			    strcasecmp(version, "HTTP/1.1")) {
				client_error(connfd, version, 505,
				    "HTTP Version not supported",
				    "Proxy does not support requested HTTP version");
				return;
			}

			// Parse the URI
			if (parse_uri(uri, &hostname, &port, &pathname) == -1) {
				client_error(connfd, method, 400, "Bad Request",
				    "Proxy could not parse the request URI");
				goto cleanup;
				return;
			}

			request_line_read = 1;

		} else {
			strcpy(request_header, buf);
		}
	}

	if (request_line_read) {
		serverfd = Open_clientfd(hostname, port);
		if (serverfd < 0) {
			client_error(connfd, "Server Connection Error", 500,
			    "Internal Server Error",
			    "Could not connect to server");
			goto cleanup;
		}

		forward_request(serverfd, connfd, request_line, request_header,
		    clientaddr);
		Close(serverfd); // Close the server connection immediately
				 // after use
		serverfd = -1;	 // Reset serverfd to indicate it's closed
	}

cleanup:
	if (hostname)
		free(hostname);
	if (port)
		free(port);
	if (pathname)
		free(pathname);
}

static void
forward_request(int serverfd, int connfd, char *request_line,
    char *request_header, struct sockaddr_storage clientaddr)
{
	char request[MAXLINE * 2 + 5]; // Maximum size for the request
	char response[MAXLINE];
	char *uri = malloc(strlen(request_line) + 1);
	strcpy(uri, request_line);
	uri += 4; // Remove "GET "
	rio_t rio;

	// Reset request buffer
	request[0] = '\0';

	// Remove " HTTP" from end of uri
	char *space_ptr = strstr(uri, " HTTP");
	if (space_ptr != NULL) {
		*space_ptr = '\0';
	}

	printf("%s", request_line);
	printf("%s\n", request_header);

	// Modify request_line and request_header
	request_line += strlen("GET http://"); // Remove "GET http://"
	request_line += strlen(request_header) -
	    8; // Remove host (-8 to get rid of \r\n and Host: )

	strcat(request, "GET ");
	strcat(request, request_line);
	strcat(request, request_header);
	printf("*** End of Request ***\n");
	printf("Request %d: Forwarding request to server:\n", counter);
	printf(request);
	printf("Connection: close\n\n");
	strcat(request, "\r\n"); // Add \r\n after the header

	Rio_readinitb(&rio, serverfd);

	// Write the request to the server
	if ((rio_writen(serverfd, request, strlen(request))) < 0) {
		// writing to server fails
		client_error(connfd, "", 504, "Gateway Timeout",
		    "Failed to send information to server");
		Close(serverfd);
		return;
	}
	printf("Sent request to server\n");
	// Rio_writen(serverfd, request, strlen(request));

	size_t total_bytes = 0;

	while (Rio_readlineb(&rio, response, MAXLINE) != 0) {
		total_bytes += strlen(response);
		Rio_writen(connfd, response, strlen(response));
		if (strcmp(response, "</html>\n") == 0) {
			break;
		}
	}

	log_entry((struct sockaddr_in *)&clientaddr, uri, total_bytes);

	uri -= 4; // Reset uri pointer to be freed
	free(uri);

	printf("*** End of Request ***\n");
	printf("Request %d: Forwarded %ld bytes from server to client\n",
	    counter, total_bytes);
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

static void *
thread(void *vargp)
{
	(void)vargp;
	Pthread_detach(pthread_self());
	while (1) {
		struct client_struct client = sbuf_remove(&sbuffer);
		proxy_doit(client.connfd, client.clientaddr); // service client
		Close(client.connfd);
	}
	return NULL;
}

static void
sbuf_init(struct sbuf *sp, int numSlots)
{
	sp->client_buf = calloc(numSlots, sizeof(struct client_struct));
	sp->numSlots = numSlots;
	sp->front = sp->rear = 0;
	sp->count = 0;
	pthread_mutex_init(&sp->mutex, NULL);
	pthread_cond_init(&sp->cond_not_empty, NULL);
	pthread_cond_init(&sp->cond_not_full, NULL);
}

static void
sbuf_insert(struct sbuf *sp, struct client_struct client)
{
	pthread_mutex_lock(&sp->mutex);

	// Wait for space if buffer is full
	while (sp->count == sp->numSlots)
		pthread_cond_wait(&sp->cond_not_full, &sp->mutex);

	// Insert the item
	sp->rear = (sp->rear + 1) % sp->numSlots;
	sp->client_buf[sp->rear] = client;
	sp->count++;

	// Signal that the buffer is not empty
	pthread_cond_signal(&sp->cond_not_empty);
	pthread_mutex_unlock(&sp->mutex);
}

// Remove and return the first item from the buffer
static struct client_struct
sbuf_remove(struct sbuf *sp)
{
	pthread_mutex_lock(&sp->mutex);

	// Wait for items if buffer is empty
	while (sp->count == 0)
		pthread_cond_wait(&sp->cond_not_empty, &sp->mutex);

	// Remove the item
	sp->front = (sp->front + 1) % sp->numSlots;
	struct client_struct client = sp->client_buf[sp->front];
	sp->count--;

	// Signal that the buffer is not full
	pthread_cond_signal(&sp->cond_not_full);
	pthread_mutex_unlock(&sp->mutex);
	return client;
}

static void
sbuf_clean(struct sbuf *sp)
{
	pthread_mutex_destroy(&sp->mutex);
	pthread_cond_destroy(&sp->cond_not_full);
	pthread_cond_destroy(&sp->cond_not_empty);
	free(sp->client_buf);
	sp->client_buf = NULL;

	sp->numSlots = 0;
	sp->front = 0;
	sp->rear = 0;
	sp->count = 0;
}

/*
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
		if (*str <html 32 || *str > 126) {
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
*/

/**
 * The HTTP/1.1 specification does not place an upper limit on the length of a
URI. Moreover, in testing your proxy at web sites with rich content, you may
encounter a URI that is longer than csapp.h’s defined MAXLINE. In other words,
you will sooner or later encounter a start or header line in an HTTP request
message that will not fit in a char array of size MAXLINE. Nonetheless, to
process the line, e.g., to perform parse uri, your proxy will need to store the
entire URI, if not the entire line, in a char array. You should explore how rio
readlineb behaves when the length of the line being read exceeds the given
buffer size
*/

/**
 *  Be careful about memory and file descriptor leaks. When the processing for
an HTTP request fails for any reason, the thread must close all open socket
descriptors and free all memory resources.
*/

/**
 * Modern web browsers and servers support persistent connections, which allow
back-to-back requests to reuse the same connection. Your proxy will not do so.
However, your browser is likely to set the headers Connection, Keep-Alive,
and/or Proxy-Connection to indicate that it would like to use persistent
connections. If you pass these headers on to the end server, it will assume that
you can support them. If you do not support persistent connections, then
subsequent requests on that connection will fail, so some or all of the web page
will not load in your browser. Therefore, you should strip the Connection,
Keep-Alive, and Proxy-Connection headers out of all requests, if they are
present. Futhermore, HTTP/1.1 requires a Connection: close header be sent if you
want the connection to close. Note that you must leave the other headers intact
as many browsers and servers make use of them and will not work correctly
without them.
*/