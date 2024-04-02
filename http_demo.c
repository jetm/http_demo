/*
 * Copyright (c) 2001,2002 Florian Schulze.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of the contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * test.c - This file is part of lwIP test
 *
 */

/* C runtime includes */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "lwip/tcpip.h"
#include "lwip/apps/altcp_tls_mbedtls_opts.h"
#include "lwip/apps/http_client.h"
#include "lwip/opt.h"

static ulong daddr;
static httpc_connection_t settings;

#define SERVER_NAME_SIZE 200
#define HTTP_PORT_DEFAULT 80
#define HTTPS_PORT_DEFAULT 443

static err_t httpc_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *pbuf,
                        err_t unused_err) {
  struct pbuf *buf;

  if (!pbuf)
    return ERR_BUF;

  for (buf = pbuf; buf != NULL; buf = buf->next) {
    memcpy((void *)daddr, buf->payload, buf->len);
    printf("downloaded chunk size %d, to addr 0x%lx\n", buf->len, daddr);
    daddr += buf->len;
  }

  altcp_recved(pcb, pbuf->tot_len);
  pbuf_free(pbuf);
  return ERR_OK;
}

static void httpc_result(void *arg, httpc_result_t httpc_result,
                         u32_t rx_content_len, u32_t srv_res, err_t err) {
  if (httpc_result == HTTPC_RESULT_OK) {
    printf("\n%d bytes successfully downloaded.\n", rx_content_len);
    exit(0);
  } else {
    printf("\nhttp error: %d\n", httpc_result);
    exit(-1);
  }
}

/* http://hostname/url */
static int parse_url(char *url, char *host, uint16_t *port, char **path) {
  char *p, *pp;
  long lport;
  bool https;

  p = strstr(url, "https://");
  if (!p) {
    p = strstr(url, "http://");
    p += strlen("http://");
    if (!p)
      return -1;
  } else {
    p += strlen("https://");
    https = true;
  }

  /* parse hostname */
  pp = strchr(p, ':');
  if (!pp)
    pp = strchr(p, '/');
  if (!pp)
    return -1;

  if (p + SERVER_NAME_SIZE <= pp)
    return -1;

  memcpy(host, p, pp - p);
  host[pp - p + 1] = '\0';

  if (*pp == ':') {
    /* parse port number */
    p = pp + 1;
    lport = strtol(p, &pp, 10);
    if (pp && *pp != '/')
      return -1;
    if (lport > 65535)
      return -1;
    *port = (uint16_t)lport;
  } else if (https) {
    *port = HTTPS_PORT_DEFAULT;
  } else {
    *port = HTTP_PORT_DEFAULT;
  }

  if (*pp != '/')
    return -1;
  *path = pp;

  return 0;
}

static int lwip_wget(char *url) {
  err_t err;
  uint16_t port;
  char server_name[SERVER_NAME_SIZE];
  httpc_state_t *connection;
  char *path;

  printf("url %s\n", url);

  err = parse_url(url, server_name, &port, &path);
  if (err)
    return -1;

  printf("downloading %s\n", url);
  memset(&settings, 0, sizeof(settings));
  settings.result_fn = httpc_result;
  err = httpc_get_file_dns(server_name, port, path, &settings, httpc_recv, NULL,
                           &connection);
  if (err != ERR_OK)
    return -2;

  return 0;
}

/* This is somewhat different to other ports: we have a main loop here:
 * a dedicated task that waits for packets to arrive. This would normally be
 * done from interrupt context with embedded hardware, but we don't get an
 * interrupt in windows for that :-) */
int main(int argc, char **argv) {
  char *url;
  int ret;

  if (argc < 2 || argc > 3)
    return -1;

  url = argv[1];

  tcpip_init(NULL, NULL);

  LOCK_TCPIP_CORE();
  ret = lwip_wget(url);
  if (ret) {
    printf("lwip_wget err %d\n", ret);
    return -1;
  }
  UNLOCK_TCPIP_CORE();
  return 0;
}
