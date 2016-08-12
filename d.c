#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include "windivert.h"

#define BUFFSIZE 65535

typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;

int main(int argc, char **argv)
{
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	UINT packetLen;
	char packet[BUFFSIZE];
	char* data, *host, *hostend;
	char target[256], temp[256], target2[256] = "http://";
	char * site;
	int i = 0;
	FILE *fp1, *fp2;
	int check, check2;

	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic only
		"ip && "                    // Only IPv4 supported
		"tcp.DstPort == 80 && "     // HTTP (port 80) only
		"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, 404, 0
	);

	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "필터 실패\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "windivert 여는데 실패\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	fp1 = fopen("C:\\mal_site.txt", "r");
	fp2 = fopen("C:\\result.txt", "a+");

	while (TRUE)
	{
		check = 0;

		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packetLen))
		{
			fprintf(stderr, "패킷 읽기 실패\n");
			continue;
		}

		// if http, find the URL
		ip_header = (PWINDIVERT_IPHDR)packet;
		tcp_header = (PWINDIVERT_TCPHDR)((char*)ip_header + (ip_header->HdrLength) * 4);
		data = (char*)((char*)tcp_header + (tcp_header->HdrLength) * 4);
		host = strstr(data, "Host: ");

		if (host != NULL)
		{
			host = host + strlen("Host: ");
			hostend = strstr(host, "\r\n");
			strncpy(target, host, 256 - 1);
			target[strlen(host) - strlen(hostend)] = '\0';
			strcat(target2, target);
		}

		while (!feof(fp1))
		{
			fscanf(fp1, "%s\n", temp);
			puts(target2);
			puts(temp);

			check2 = strncmp(target2, temp, sizeof(target2));

			if(!check2)
			{
				fprintf(fp2, "유해사이트 접속이 차단되었습니다. 차단된 url은 %s 입니다.\n", target2);

				check = 1;
				break;
			}
		}

		if (!check)
		{
			if (!WinDivertSend(handle, packet, packetLen, &addr, NULL))
			{
				fprintf(stderr, "패킷 보내기 실패\n");
				continue;
			}

		}
	}

	fclose(fp1);
	fclose(fp2);
	WinDivertClose(handle);
}