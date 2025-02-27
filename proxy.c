/*
 * COMP 321 Project 6: Web Proxy
 *
 * This program implements a multithreaded HTTP proxy.
 *
 * John Talghader jat8, Anjali Yamasani ay50
 */

#include <assert.h>

#include "csapp.h"
#define NTHREADS 25
#define SBUFSIZE 100

struct client_struct {
	struct sockaddr_storage clientaddr;
	int connfd;
	char *hostname;
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
static void handleLongLine(rio_t *rio_ptr, char **line);
static void forward_request(int clientfd, int connfd, char *request,
    char *request_line, struct sockaddr_storage clientaddr);
static void log_entry(struct sockaddr_in *sockaddr, char *uri, size_t size);
static int build_request(rio_t *rio, int connfd, char **request,
    char *request_line);
static void *thread(void *vargp);
static void sbuf_init(struct sbuf *sp, int n);
static void sbuf_insert(struct sbuf *sp, struct client_struct client);
static struct client_struct sbuf_remove(struct sbuf *sp);
static void sbuf_clean(struct sbuf *sp);

/* Global variables */
int counter = -1;
FILE *proxy_log = NULL;
struct sbuf sbuffer; /* Shared buffer of connected descriptors */
// char *http_request_flag; /* HTTP/1.0 or HTTP/1.1 */

/*
 * Requires:
 *   argv[1]: A string representing the port number 
 *
 * Effects:
 *   Replicates a proxy. Opens a socket and continuously listens for incoming
 *   client connections. Creates a number of threads to deal with the client
 *   connections in case requests are sent in concurrently. Finally opens and
 *   closes a log file to log the connections made to the proxy and server
 *   responses to HTTP requests.
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

	// Creates worker threads
	for (int i = 0; i < NTHREADS; i++) {
		Pthread_create(&tid, NULL, thread, NULL);
	}

	// Iterate through all clients trying to connect to proxy
	while (1) {
		// Accept incoming client connection
		struct sockaddr_storage clientaddr;
		clientlen = sizeof(clientaddr);
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

		client.hostname = client_hostname;

		if (res != 0) {
			fprintf(stderr, "Getnameinfo error: %s\n",
			    gai_strerror(res));
			// Handle error, for example, by continuing to the next
			// iteration of the loop.
			continue;
		}

		sbuf_insert(&sbuffer, client);
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

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Builds the request string and sends it to the end server for a response.
*/
static void
proxy_doit(int connfd, struct sockaddr_storage clientaddr)
{
	char *request;
	char *request_line = malloc(MAXLINE + 1);
	size_t n;
	int serverfd;
	rio_t rio;

	// malloc space for request
	request = malloc(1);
	request[0] = '\0';
	rio_readinitb(&rio, connfd);
	n = rio_readlineb(&rio, request_line, MAXLINE); // Get the request line

	// Handle the case where request_line is larger than MAXLINE
	if (n == MAXLINE - 1) {
		handleLongLine(&rio, &request_line);
	}

	// Build the actual request to be sent to the end server
	serverfd = build_request(&rio, connfd, &request, request_line);
	if (serverfd != -1) {
		forward_request(serverfd, connfd, request, request_line, clientaddr);
		Close(serverfd);
	}

	free(request);
}

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Handles the case in which a given line is larger than MAXLINE. Continuously
 *   mallocs more space for the line and adds the missing parts in.
*/
static void
handleLongLine(rio_t *rio_ptr, char **line)
{
	size_t line_size, curr_size;
	char curr_buf[MAXLINE];
	memset(curr_buf, 0, MAXLINE);
	curr_size = line_size = MAXLINE - 1;

	// Keep iterating until we find an endline character
	while(curr_buf[curr_size - 1] != '\n') {
		curr_size = rio_readlineb(rio_ptr, curr_buf, MAXLINE);
		line_size += curr_size;
		
		// Realloc memory for line and concatenate the missing pieces
		*line = realloc(*line, line_size);
		strcat(*line, curr_buf);
	}
}

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Forwards the request to the end server and calls log_entry to make a log
 *   of the request and response in proxy.log.
*/
static void
forward_request(int serverfd, int connfd, char *request, char *request_line,
    struct sockaddr_storage clientaddr)
{
	char response[MAXLINE];
	char uri[MAXLINE];
	rio_t server_rio;

	// Obtain uri
	sscanf(request_line, "%*s %s %*s", uri);

	// Print to stdout to match reference solution
	printf("*** End of Request ***\n");
	printf("Request %d: Forwarding request to server:\n", counter);
	printf(request);

	// Write the request to the server
	rio_writen(serverfd, request, strlen(request));

	// Initialize server to be read from
	rio_readinitb(&server_rio, serverfd);

	size_t total_bytes = 0;
	size_t n;

	printf("*** End of Request ***\n");

	// Read the server's response to the request
	while ((n = rio_readnb(&server_rio, response, MAXLINE)) != 0) {
		total_bytes += n;

		// Write the response to the client
		rio_writen(connfd, response, n);

		// Print to stdout to match reference solution
		printf("Request %d: Forwarded %ld bytes from server to client\n"
		, counter, n);
	}

	// Make the log entry
	log_entry((struct sockaddr_in *)&clientaddr, uri, total_bytes);
}

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Write a log of the request to the proxy.log file containing the time of
 *   the request, the host address, and the size of the server's response.
*/
static void
log_entry(struct sockaddr_in *sockaddr, char *uri, size_t size)
{
	char *entry;
	entry = create_log_entry(sockaddr, uri, size);

	// Write to the log file and free the entry string
	fprintf(proxy_log, "%s\n", entry);
	free(entry);
	fflush(proxy_log);
}

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Builds the request to be sent to the end server and sets up the file
 *   descriptor connecting the proxy to the end server.
*/
static int
build_request(rio_t *rio_ptr, int connfd, char **request, char *request_line)
{
	char method[MAXLINE], uri[MAXLINE], version[MAXLINE];
	char *hostname = NULL, *port = NULL, *pathname = NULL;
	char *buf = malloc(MAXLINE + 1);
	size_t request_size, buf_size;
	int serverfd;

	// Parse the request line
	if (sscanf(request_line, "%s %s %s", method, uri, version) < 3) {
		client_error(connfd, method, 400, "Bad Request",
		    "Proxy received a malformed request line");
		return -1;
	}

	// Check if method is GET or not
	if (strcasecmp(method, "GET") != 0) {
		client_error(connfd, method, 501, "Not implemented",
		    "Proxy does not implement this method");
		return -1;
	}

	// Parse the URI
	if (parse_uri(uri, &hostname, &port, &pathname) == -1) {
		client_error(connfd, method, 400, "Bad Request",
		    "Proxy could not parse the request URI");
		return -1;
	}

	// Add the properly formatted request line to request
	request_size = strlen(method) + strlen(pathname) + strlen(version) + 5; 
	// Add 5, two for space, two for carriage and endline character, one 
	// for null terminator
	*request = realloc(*request, request_size);
	strcpy(*request, method);
	strcat(*request, " ");
	strcat(*request, pathname);
	strcat(*request, " ");
	strcat(*request, version);
	strcat(*request, "\r\n");

	// Move to first request header
	buf_size = rio_readlineb(rio_ptr, buf, MAXLINE);
	if (buf_size == MAXLINE - 1) {
		handleLongLine(rio_ptr, &buf);
	}

	// Print to stdout to match reference solution
	printf("%s", request_line);

	// Iterate until there are no more request headers
	while (strcmp(buf, "\r\n") != 0) {
		// Print to stdout to match reference solution
		printf("%s\n", buf);

		// Strip unwanted headers out of request
		if (strstr(buf, "Connection") == NULL &&
		    strstr(buf, "Keep-Alive") == NULL &&
		    strstr(buf, "Proxy-Connection") == NULL) {
			request_size += strlen(buf);
			*request = realloc(*request, request_size);
			strcat(*request, buf);
		}

		buf_size = rio_readlineb(rio_ptr, buf, MAXLINE);
		if (buf_size == MAXLINE - 1) {
			handleLongLine(rio_ptr, &buf);
		}
	}

	// Add "Connection: close" header to request
	request_size += strlen("Connection: close\r\n\r\n");
	*request = realloc(*request, request_size);
	strcat(*request, "Connection: close\r\n\r\n");

	serverfd = Open_clientfd(hostname, port);
	if (serverfd == -1) {
		fprintf(stderr, "Error: Error opening serverfd");
		free(hostname);
		free(port);
		free(pathname);
		return -1;
	}

	free(hostname);
	free(port);
	free(pathname);

	return serverfd;
}

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Detaches the calling thread and enters an infinite loop to continuously
 *   service client requests.
*/
static void *
thread(void *vargp)
{
	(void)vargp;
	Pthread_detach(pthread_self());
	while (1) {
		struct client_struct client = sbuf_remove(&sbuffer);
		counter++;
		printf("\nRequest %d: Received request from client %s\n",
		    counter, client.hostname);
		proxy_doit(client.connfd, client.clientaddr); // service client
		Close(client.connfd);
	}
	return NULL;
}

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Initializes the shared buffer with the given number of slots.
 *   Allocates memory for the buffer and initializes its fields.
 *   Initializes the mutex and condition variables used for synchronization.
*/
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

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Locks the mutex and inserts the item into the buffer when space is
 *   available. Also then signals that the buffer is not empty.
*/
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

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Remove and return the first item from the buffer
*/
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

/*
 * Requires:
 *   Nothing.
 * 
 * Effects:
 *   Destroys and cleans up the mutex and client_buf
*/
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