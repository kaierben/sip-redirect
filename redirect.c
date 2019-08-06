/********************************************
 *	简单的SIP重定向服务
 *  该版本只支持UDP协议， 并且以单线程运行。
 *	用法: 在命令行中输入参数： --port=$port server1 [server2] [server3] ...
 *		其中--port指定本服务器监听的UDP端口，无该参数则默认5060
 *		serverN 是真实SIP服务器的地址，可以是 IP 或 IP:Port的格式。
 *		serverN可以是任意多个。
 *  本程序不应该处理 ”应答“ 消息，如果收到应答消息包则丢弃
 *	如果收到ACK请求，则不进行重定向。
 *  如果收到OPTIONS请求，则返回200 OK
 *  如果收到REGISTER请求，则判断上次的相同号码重定向的地址，有则转移到前次地址，否则保存地址信息
 *	如果收到其它请求，先查找地址信息表，如果有则按前次地址重定向，否则随机一个地址重定向
 *
 *  内部使用了一个哈希表，表中每个节点是一个单向链表。
 *	每个节点又有r_next, r_prev建立双向链表。双向链表和哈希表并行存在。
 *
 * compile:
 *		gcc -O3 -Wall -o redirect redirect.c
 * usage:
 *		redirect --port=$port server1 [server2] [server3] [...]
 *		--port:		UDP Port for SIP
 *		server1:	Real SIP Server
 * license: GPL
 *
 * @file redirect.c
 * @author 李雄峰 li xiongfeng
 * @email lxf_programmer@163.com
 *
 ********************************************/
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <time.h>

struct hash_node
{
	// 哈希节点。
	unsigned int h;
	char* username;
	char* server;
	int timeout;
	struct hash_node* c_next; // 哈希命中后的单链表
	struct hash_node* r_prev, * r_next;// 所有节点的双向链表，用于快速检索。
};

struct hash_table
{
	// 哈希表
	unsigned int capacity; // 容量大小，作为模数。
	unsigned int size; // fact size, 实际大小。
	struct hash_node** tables; // array, 数组，长度为capacity, 当前版本长度不可变，节点是一个单链表。
	struct hash_node* r_link;  // double link, 双向链表，保存所有节点。
};

struct sip_message
{
	// 解析后的SIP消息。只存储REQUEST消息。
	// 不保存BODY。
	char* method;
	char* callid;
	char* from;
	char* to;
	char* cseq;
	char* via[16];// via最多16个。
};

static unsigned int hash(const char* str)
{
	// 哈希函数，与MySQL中的相同。
	unsigned int h;
	unsigned char* p;
	for (h = 0, p = (unsigned char*)str; *p; p++)
		h = 31 * h + *p;
	return h;
}

static int sip_parse(struct sip_message*  msg, char* buf)
{
	// 解析SIP消息。保存于msg中。
	char* str, * val;
	int via = 0;

	memset(msg, 0, sizeof(struct sip_message));
	str = strchr(buf, ' ');
	if (NULL == str) return -1;

	*str = 0;
	msg->method = buf;
	// 如果是应答消息，则不处理.
	if (!strcasecmp(msg->method, "SIP/2.0"))
		return -1;

	str = strchr(str + 1, '\n');
	if (NULL == str) return -1;
	str++;
	while (str)
	{
		buf = str;
		str = strchr(buf, ':');
		if (NULL == str) break;
		*str = 0;
		str++;
		val = str;
		str = strchr(val, '\r');
		if (NULL == str) break;
		*str = 0;
		str++;	str++;

		if (!strcasecmp(buf, "Call-ID") || !strcmp(buf,"i")) msg->callid = val;
		else if (!strcasecmp(buf, "From") || !strcmp(buf,"f")) msg->from = val;
		else if (!strcasecmp(buf, "To") || !strcmp(buf,"t")) msg->to = val;
		else if (!strcasecmp(buf, "CSeq")) msg->cseq = val;
		else if (!strcasecmp(buf, "Via") || !strcmp(buf,"v")) if (via<16) msg->via[via++] = val;
	}
	if (NULL == msg->callid || NULL == msg->from || 
		NULL == msg->to || NULL == msg->callid || 0 == via)
		return -1;

	return 0;
}

static int running = 1; // 运行标记， 如果按Ctrl+C，或执行kill则设置为0.
static struct hash_table ht = { 0 }; // 存储注册信息。

static void signal_abort(int sign)
{
	if ((sign == SIGTERM) || (sign == SIGINT))
		running = 0;
}

static int get_username(const char* to, char* username, int size)
{
	// 获取号码信息。
	const char* str, * tel;
	str = strchr(to, '<');
	if (NULL == str)
		return -1;
	str++;
	str = strchr(str, ':');
	if (NULL == str)return -1;
	str++;
	tel = str;

	while (*str)
	{
		if ('>' == *str || '@' == *str || ';' == *str)
			break;
		str++;
	}
	if (str - tel >= size)
		return -1;
	strncpy(username, tel, str - tel);
	username[str - tel] = 0;
	return 0;
}

int init_location(unsigned int size)
{
	// 初始化哈希表。
	ht.capacity = size;
	ht.size = 0;
	ht.tables = (struct hash_node**)malloc(sizeof(struct hash_node*) * size);
	if (NULL == ht.tables)
		return  - 1;
	memset(ht.tables,0, sizeof(struct hash_node*) * size);
	return 0;
}

const char* find_location(const char* username)
{
	// 在哈希表中查找号码，返回地址信息。
	unsigned int h = hash(username);
	unsigned int i = h % ht.capacity;
	const struct hash_node* l = ht.tables[i];
	while (l)
	{
		if (l->h == h && !strcmp(username, l->username))
			break;
		l = l->c_next;
	}
	if (NULL == l) return NULL;
	return l->server;
}

void save_location(const char* username, const char* server)
{
	// 保存号码，地址信息到哈希表中。
	unsigned int h = hash(username);
	unsigned int i = h % ht.capacity;
	struct hash_node* l = ht.tables[i];
	assert(username && server);
	while (l)
	{
		if (l->h == h && !strcmp(username, l->username))
			break;
		l = l->c_next;
	}
	if (l)
	{
		if (strcmp(server, l->server))
		{
			free(l->server);
			l->server = strdup(server);
		}
		l->timeout = 0;
	}
	else
	{
		l = (struct hash_node*)malloc(sizeof(struct hash_node));
		if (NULL == l) return;
		l->username = strdup(username);
		l->server = strdup(server);
		l->h = h;
		l->timeout = 0;
		// 保存于数组中，数组的每个节点都是一个单链表。
		l->c_next = ht.tables[i];
		ht.tables[i] = l;

		// 保存到双向链表中。
		l->r_next = ht.r_link;
		l->r_prev = NULL;
		if (ht.r_link) ht.r_link->r_prev = l;
		ht.r_link = l;

		ht.size++;
	}
}

void scan_location(int diff)
{
	// 扫描号码/地址信息，检查超时，删除超时的信息。
	unsigned int h;
	struct hash_node* p, * next;
	struct hash_node* arr, * pr;

	p = ht.r_link;
	while (p)
	{
		next = p->r_next;
		p->timeout += diff;
		if (p->timeout >= 3600) // 按最大3600秒钟超时。
		{
			if (next) next->r_prev = p->r_prev;
			if (p->r_prev) p->r_prev->r_next = next;
			if (ht.r_link == p) ht.r_link = next;

			h = p->h % ht.capacity;
			arr = ht.tables[h];
			pr = NULL;
			while (arr)
			{
				if (arr == p)
				{
					if (pr) pr->c_next = p->c_next;
					else ht.tables[h] = p->c_next;
					break;
				}
				pr = arr;
				arr = arr->c_next;
			}
			free(p->username);
			free(p->server);
			free(p);
		}
		p = next;
	}
}

int main(int argc, char* argv[])
{
	int i;
	int fd = -1, port = 5060;
	unsigned int j = 0, server_count = 0;
	struct sockaddr_in sa = { 0 };
	char** server;
	struct sip_message msg;
	time_t last, now;

	if (argc < 2)
	{
		printf("usage: %s [--port=$port] server1 [server2] [server3] ...\n", argv[0]);
		return -1;
	}
	server = (char **)malloc((argc-1) * sizeof(char *));
	if (0 == server) return -1;
	memset(server, 0, (argc - 1) * sizeof(char *));
	for (i = 1; i < argc; i++)
	{
		if (!strncmp(argv[i], "--port=", 7))port = atoi(argv[i] + 7);
		else server[j++] = strdup(argv[i]);
	}
	server_count = j;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = 0;
	if (0 != bind(fd, (struct sockaddr*) & sa, sizeof(struct sockaddr_in)))
	{
		close(fd);
		return -1;
	}
	printf("listen port %d\n", port);
	if (0 != init_location(4096))
	{
		close(fd);
		return -1;
	}

	running = 1;
	signal(SIGINT, signal_abort);
	signal(SIGTERM, signal_abort);
	time(&last);
	while (running)
	{
		char rx_buf[4000];
		char tx_buf[4000];
		char username[32];
		int len;
		socklen_t fromlen = sizeof(struct sockaddr_in);
		fd_set fs;
		struct timeval tv = { 0,500000 };

		FD_ZERO(&fs);
		FD_SET(fd, &fs);
		if (select(fd + 1, &fs, NULL, NULL, &tv) <= 0)
		{
			// 空闲时检查， 如果有消息，则不检查。
			time(&now);
			if (last != now)
			{
				scan_location((int)(now - last));
				last = now;
			}
			continue;
		}

		memset(&sa, 0, sizeof(struct sockaddr_in));
		len = recvfrom(fd, rx_buf, sizeof(rx_buf) - 1, 0, (struct sockaddr*) & sa, &fromlen);
		if (len <= 32) continue;
		rx_buf[len] = '\0';

		if (0 != sip_parse(&msg, rx_buf)) continue;
		if (!strcasecmp(msg.method, "ACK")) continue;
		if (!strcasecmp(msg.method, "CANCEL") ||
			!strcasecmp(msg.method, "OPTIONS"))
		{
			len = snprintf(tx_buf, sizeof(tx_buf), "SIP/2.0 200 OK\r\n");
		}
		else
		{
			const char* dest = server[hash(msg.callid) % server_count];
			if (0 == get_username(msg.to, username, sizeof(username)))
			{
				const char * tmp = find_location(username);
				if (NULL == tmp)
				{
					if (!strcasecmp(msg.method, "REGISTER"))
					{
						save_location(username, dest);
					}
				}
				else
				{
					dest = tmp;
				}
			}

			len = snprintf(tx_buf, sizeof(tx_buf), "SIP/2.0 302 Moved Permanently\r\n");			
			len += snprintf(tx_buf + len, sizeof(tx_buf) - len - 1, "Contact: <sip:%s>\r\n", dest);
		}
		for (i = 0; i < 16; i++)
		{
			if (NULL == msg.via[i]) break;
			len += snprintf(tx_buf + len, sizeof(tx_buf) - len - 1, "Via: %s\r\n", msg.via[i]);
		}
		len += snprintf(tx_buf + len, sizeof(tx_buf) - len - 1, "From: %s\r\n", msg.from);
		len += snprintf(tx_buf + len, sizeof(tx_buf) - len - 1, "To: %s\r\n", msg.to);
		len += snprintf(tx_buf + len, sizeof(tx_buf) - len - 1, "Call-ID: %s\r\n", msg.callid);
		len += snprintf(tx_buf + len, sizeof(tx_buf) - len - 1, "CSeq: %s\r\n", msg.cseq);
		len += snprintf(tx_buf + len, sizeof(tx_buf) - len - 1, "Content-Length: 0\r\n\r\n");
		sendto(fd, tx_buf, len, 0, (struct sockaddr*) & sa, sizeof(struct sockaddr_in));
	}
	close(fd);
	return 0;
}
