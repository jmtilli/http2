#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

SSL *ssl;

char writebuf[32768];
int to_write;


int want_write;
int want_write_isread;
int want_read_iswrite;

char expected_read[1024];
int expected_read_pos;
int expected_read_sz;

int read_wrap(void)
{
  int err;
  char buf[1025];
  printf("read_wrap\n");
  ERR_clear_error();
  err = SSL_read(ssl, buf, expected_read_sz - expected_read_pos);
  if (err > 0)
  {
    if (memcmp(buf, expected_read + expected_read_pos, err) != 0)
    {
      printf("Nonexpected request\n");
      exit(1);
    }
    expected_read_pos += err;
    if (expected_read_pos == expected_read_sz)
    {
      char *response = 
        "HTTP/1.1 301 Moved Permanently\r\n"
        "Server: CloudFront\r\n"
        "Date: Tue, 12 Jun 2018 13:00:29 GMT\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 183\r\n"
        "Connection: keep-alive\r\n"
        "Location: https://localhost/\r\n"
        "X-Cache: Redirect from cloudfront\r\n"
        "Via: 1.1 773455c70e671b68419317a9c32aa999.cloudfront.net (CloudFront)\r\n"
        "X-Amz-Cf-Id: B-PkOGnMM6ze07I9Im56LivwNk4ylWlGwx9EtCCDbV3H-o2DO5tTDA==\r\n"
        "\r\n";
      memcpy(writebuf, response, strlen(response));
      to_write = strlen(response);
      want_write = 1;
    }
  }
  if (err < 0)
  {
    int ssl_err = SSL_get_error(ssl, err);
    if (ssl_err == SSL_ERROR_WANT_WRITE)
    {
      want_write = 1;
      want_write_isread = 1;
    }
    if (ssl_err == SSL_ERROR_WANT_READ)
    {
    }
  }
  if (err == 0)
  {
    return 1;
  }
  return 0;
}

void write_wrap(void)
{
  int ret;
  if (!want_write && !want_read_iswrite)
  {
    abort();
  }
  if (want_write_isread)
  {
    abort();
  }
  want_read_iswrite = 0;
  printf("write_wrap towr %d\n", to_write);
  ERR_clear_error();
  ret = SSL_write(ssl, writebuf, to_write);
  printf("write_wrap ret %d\n", ret);
  if (ret > 0)
  {
    printf("Wrote %d bytes\n", ret);
    memmove(writebuf, writebuf+ret, to_write-ret);
    to_write -= ret;
    if (to_write == 0)
    {
      want_write = 0;
      want_write_isread = 0;
      SSL_shutdown(ssl);
    }
  }
  else if (ret < 0)
  {
    int ssl_err = SSL_get_error(ssl, ret);
    if (ssl_err == SSL_ERROR_WANT_WRITE)
    {
      printf("want write\n");
      want_write = 1;
      want_write_isread = 0;
    }
    else if (ssl_err == SSL_ERROR_WANT_READ)
    {
      printf("want read\n");
      want_write = 0;
      want_read_iswrite = 1;
    }
    else
    {
      long error = ERR_get_error();
      char error_string[1024];
      ERR_error_string_n(error, error_string, sizeof(error_string));
      printf("could not SSL_write (returned -1): %s\n", error_string);
    }
  }
  else if (to_write == 0)
  {
    want_write = 0;
    want_write_isread = 0;
    SSL_shutdown(ssl);
  }
}

int main(int argc, char **argv)
{
  int srvfd;
  int connfd;
  struct sockfd;
  struct sockaddr_in sin;
  char *request;
  int enable = 1;

  SSL_CTX *ctx;

  srvfd = socket(AF_INET, SOCK_STREAM, 0);
  if (srvfd < 0)
  {
    abort();
  }

  if (setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
  {
    printf("setsockopt(SO_REUSEADDR) failed\n");
    exit(1);
  }

  sin.sin_family = AF_INET;
  sin.sin_port = htons(8443);
  sin.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(srvfd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
  {
    abort();
  }

  listen(srvfd, 5);
  connfd = accept(srvfd, NULL, 0);

  SSL_library_init();
  SSL_load_error_strings();

#if OPENSSL_VERSION_NUMBER >= 0x1010000f
  ctx = SSL_CTX_new(TLS_server_method());
#else
  ctx = SSL_CTX_new(TLSv1_2_server_method());
#endif
  //SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  SSL_CTX_set_ecdh_auto(ctx, 1);
  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
  }

  ssl = SSL_new(ctx);
  //SSL_set_tlsext_host_name(ssl, "localhost");
  SSL_set_fd(ssl, connfd);

  //const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
  const char* const PREFERRED_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20";

  int res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
  if (res != 1)
  {
    printf("Ciphers\n");
    exit(1);
  }

  res = SSL_accept(ssl);
  if (res > 0)
  {
    printf("Connected\n");
  }
  else if (res == 0)
  {
    printf("could not accept\n");
  }
  else if (res < 0)
  {
    long error = SSL_get_error(ssl, res);
    char error_string[1024];
    ERR_error_string_n(error, error_string, sizeof(error_string));
    printf("could not SSL_accept (returned -1): %s\n", error_string);
    ERR_print_errors_fp(stderr);
    exit(1);
  }


  if (fcntl(connfd, F_SETFL, fcntl(connfd, F_GETFL) | O_NONBLOCK) < 0)
  {
    abort();
  }

  printf("Got here\n");

  request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
  expected_read_sz = strlen(request);
  memcpy(expected_read, request, expected_read_sz);
  expected_read_pos = 0;

  for (;;)
  {
    fd_set readfds, writefds;

    FD_ZERO(&readfds);
    FD_SET(connfd, &readfds);
    if (want_write)
    {
      FD_ZERO(&writefds);
      FD_SET(connfd, &writefds);
    }
    select(connfd+1, &readfds, &writefds, NULL, NULL);
    if (FD_ISSET(connfd, &readfds))
    {
      if (want_read_iswrite)
      {
        printf("1 calling write_wrap\n");
        write_wrap();
      }
      else
      {
        printf("2 calling read_wrap\n");
        if (read_wrap())
        {
          break;
        }
      }
    }
    if (FD_ISSET(connfd, &writefds) && want_write)
    {
      if (want_write_isread)
      {
        printf("3 calling read_wrap\n");
        if (read_wrap())
        {
          break;
        }
      }
      else
      {
        printf("4 calling write_wrap\n");
        write_wrap();
      }
    }
  }
}
