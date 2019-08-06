/********************************************
 *	�򵥵�SIP�ض������
 *  �ð汾ֻ֧��UDPЭ�飬 �����Ե��߳����С�
 *	�÷�: ������������������� --port=$port server1 [server2] [server3] ...
 *		����--portָ����������������UDP�˿ڣ��޸ò�����Ĭ��5060
 *		serverN ����ʵSIP�������ĵ�ַ�������� IP �� IP:Port�ĸ�ʽ��
 *		serverN��������������
 *  ������Ӧ�ô��� ��Ӧ�� ��Ϣ������յ�Ӧ����Ϣ������
 *	����յ�ACK�����򲻽����ض���
 *  ����յ�OPTIONS�����򷵻�200 OK
 *  ����յ�REGISTER�������ж��ϴε���ͬ�����ض���ĵ�ַ������ת�Ƶ�ǰ�ε�ַ�����򱣴��ַ��Ϣ
 *	����յ����������Ȳ��ҵ�ַ��Ϣ���������ǰ�ε�ַ�ض��򣬷������һ����ַ�ض���
 *
 *  �ڲ�ʹ����һ����ϣ������ÿ���ڵ���һ����������
 *	ÿ���ڵ�����r_next, r_prev����˫������˫������͹�ϣ���д��ڡ�
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
 * @author ���۷� li xiongfeng
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
	// ��ϣ�ڵ㡣
	unsigned int h;
	char* username;
	char* server;
	int timeout;
	struct hash_node* c_next; // ��ϣ���к�ĵ�����
	struct hash_node* r_prev, * r_next;// ���нڵ��˫���������ڿ��ټ�����
};

struct hash_table
{
	// ��ϣ��
	unsigned int capacity; // ������С����Ϊģ����
	unsigned int size; // fact size, ʵ�ʴ�С��
	struct hash_node** tables; // array, ���飬����Ϊcapacity, ��ǰ�汾���Ȳ��ɱ䣬�ڵ���һ��������
	struct hash_node* r_link;  // double link, ˫�������������нڵ㡣
};

struct sip_message
{
	// �������SIP��Ϣ��ֻ�洢REQUEST��Ϣ��
	// ������BODY��
	char* method;
	char* callid;
	char* from;
	char* to;
	char* cseq;
	char* via[16];// via���16����
};

static unsigned int hash(const char* str)
{
	// ��ϣ��������MySQL�е���ͬ��
	unsigned int h;
	unsigned char* p;
	for (h = 0, p = (unsigned char*)str; *p; p++)
		h = 31 * h + *p;
	return h;
}

static int sip_parse(struct sip_message*  msg, char* buf)
{
	// ����SIP��Ϣ��������msg�С�
	char* str, * val;
	int via = 0;

	memset(msg, 0, sizeof(struct sip_message));
	str = strchr(buf, ' ');
	if (NULL == str) return -1;

	*str = 0;
	msg->method = buf;
	// �����Ӧ����Ϣ���򲻴���.
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

static int running = 1; // ���б�ǣ� �����Ctrl+C����ִ��kill������Ϊ0.
static struct hash_table ht = { 0 }; // �洢ע����Ϣ��

static void signal_abort(int sign)
{
	if ((sign == SIGTERM) || (sign == SIGINT))
		running = 0;
}

static int get_username(const char* to, char* username, int size)
{
	// ��ȡ������Ϣ��
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
	// ��ʼ����ϣ��
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
	// �ڹ�ϣ���в��Һ��룬���ص�ַ��Ϣ��
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
	// ������룬��ַ��Ϣ����ϣ���С�
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
		// �����������У������ÿ���ڵ㶼��һ��������
		l->c_next = ht.tables[i];
		ht.tables[i] = l;

		// ���浽˫�������С�
		l->r_next = ht.r_link;
		l->r_prev = NULL;
		if (ht.r_link) ht.r_link->r_prev = l;
		ht.r_link = l;

		ht.size++;
	}
}

void scan_location(int diff)
{
	// ɨ�����/��ַ��Ϣ����鳬ʱ��ɾ����ʱ����Ϣ��
	unsigned int h;
	struct hash_node* p, * next;
	struct hash_node* arr, * pr;

	p = ht.r_link;
	while (p)
	{
		next = p->r_next;
		p->timeout += diff;
		if (p->timeout >= 3600) // �����3600���ӳ�ʱ��
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
			// ����ʱ��飬 �������Ϣ���򲻼�顣
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
