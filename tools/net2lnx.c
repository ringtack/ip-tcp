#include <stddef.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define HOST_MAX_LENGTH 256 // RFC 2181

typedef struct node_s {
	char name[64];
	char host[64];
	uint16_t port;
	FILE *f;
	struct node_s *next;
} node_t;


int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s [.net file]", argv[0]);
		return 1;
	}

	FILE *f;
	node_t *nodes = NULL, *node, *other;
	char first[HOST_MAX_LENGTH], second[HOST_MAX_LENGTH], third[HOST_MAX_LENGTH];
	int ret, isNodeDone = 0;
	uint16_t port = 5000;
	uint32_t addr = 3232235521; // 192. 168. 0. 1
	uint32_t temp;

	if ((f = fopen(argv[1], "r")) == NULL) {
		perror("fopen");
		return 1;
	}

	if (feof(f)) {
		fclose(f);
		return 0;
	}

	while (!feof(f)) {
		ret = fscanf(f, "%s %s %s", first, second, third);
		if (ret == EOF) {
			ret = 0; break;
		}
		if (!strcmp("node", first)) {
			if (isNodeDone) {
				fprintf(stderr, "error: node should come before interfaces\n");
				ret = -1;
				break;
			}
			if (!(node = malloc(sizeof(node_t)))) {
				perror("malloc");
				ret = -1;
				break;
			}
			strcpy(node->name, second);
			strcpy(node->host, third);
			strcat(second, ".lnx");
			if ((node->f = fopen(second, "w")) == NULL) {
				perror("fopen");
				free(node);
				ret = -1;
				break;
			}
			node->port = port;
			fprintf(node->f, "%s %d\n", third, port++);
			node->next = nodes;
			nodes = node;

		} else {
			isNodeDone = 1;
			if (strcmp("<->", second)) {
				fprintf(stderr, "error: interface should be A <-> B\n");
				ret = -1;
				break;
			}
			int isOtherFirst = 0;
			for (node = nodes; node; node = node->next) {
				if (!strcmp(node->name, first)) {
					isOtherFirst = 0;
					break;
				} else if (!strcmp(node->name, third)) {
					isOtherFirst = 1;
					break;
				}
			}
			if (!node) {
				fprintf(stderr, "error: interface includes unknown node\n");
				ret = -1;
				break;
			}
			for (other = nodes; other; other = other->next) {
				if (isOtherFirst && !strcmp(other->name, first)) {
					temp = addr + 1;
					fprintf(other->f, "%s %d %d.%d.%d.%d %d.%d.%d.%d\n", node->host, (int) node->port,
							addr >> 24, (addr>>16)&0xff, (addr>>8)&0xff, addr & 0xff,
							temp >> 24, (temp>>16)&0xff, (temp>>8)&0xff, temp & 0xff);
					fprintf(node->f, "%s %d %d.%d.%d.%d %d.%d.%d.%d\n", other->host, (int) other->port,
							temp >> 24, (temp>>16)&0xff, (temp>>8)&0xff, temp & 0xff,
							addr >> 24, (addr>>16)&0xff, (addr>>8)&0xff, addr & 0xff);
					addr += 2;
					break;
				} else if (!isOtherFirst && !strcmp(other->name, third)) {
					temp = addr + 1;
					fprintf(node->f, "%s %d %d.%d.%d.%d %d.%d.%d.%d\n", other->host, (int) other->port,
							addr >> 24, (addr>>16)&0xff, (addr>>8)&0xff, addr & 0xff,
							temp >> 24, (temp>>16)&0xff, (temp>>8)&0xff, temp & 0xff);
					fprintf(other->f, "%s %d %d.%d.%d.%d %d.%d.%d.%d\n", node->host, (int) node->port,
							temp >> 24, (temp>>16)&0xff, (temp>>8)&0xff, temp & 0xff,
							addr >> 24, (addr>>16)&0xff, (addr>>8)&0xff, addr & 0xff);
					addr += 2;
					break;
				}
			}
			if (!node) {
				fprintf(stderr, "error: interface includes unknown node\n");
				ret = -1;
				break;
			}
		}
	}
	for (node = nodes; node; node = other) {
		other = node->next;
		fclose(node->f);
		free(node);
	}
	return 0;
}
