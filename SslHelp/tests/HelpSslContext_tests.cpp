// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#define NOMINMAX
#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>

#include <array_deque.h>
#include <event.h>
#include <HelpSslCustomBio.h>
#include <HelpSslContext.h>
#include <HelpSslSsl.h>

#include "auto_thread.h"

using namespace clv;
using namespace clv::OpenSSL;

struct SyncBuffer
{
    SyncBuffer()
        : mSignal(), mBuffer(8000) {};
    Event mSignal;
    ArrayDeque<char> mBuffer;
};

constexpr char CustomBioTypeName[] = "CtxTestBioType";
/**
     @brief A custom BIO type for testing SSL contexts.
     @details Uses the new CRTP-based SslCustomBio pattern.
     */
struct CtxTestBioType : public SslCustomBio<CtxTestBioType, BIO_TYPE_SOURCE_SINK, CustomBioTypeName>
{
    using Base = SslCustomBio<CtxTestBioType, BIO_TYPE_SOURCE_SINK, CustomBioTypeName>;
    friend Base;
    friend BioMethodStatics<CtxTestBioType>;

    // Required static methods for the CRTP base
    static constexpr int bio_type()
    {
        return BIO_TYPE_SOURCE_SINK;
    }
    static constexpr const char *name()
    {
        return CustomBioTypeName;
    }

    /**
     @brief Read data from the BIO.
     @param out The buffer to which the read data will be written.
     @param size The maximum number of bytes to read.
     @return The number of bytes read from the BIO.
     */
    int read(char *out, int size)
    {
        std::cout << mTag << "Waiting to read[" << size << "]\n";
        auto lock = mData.mSignal.Wait([this]()
        { return !mData.mBuffer.empty(); });
        auto read_size = std::min(size, static_cast<int>(mData.mBuffer.size()));
        std::copy(mData.mBuffer.begin(), mData.mBuffer.begin() + read_size, out);
        mData.mBuffer.free_head(static_cast<std::size_t>(read_size));
        mData.mBuffer.set_headroom(0);
        std::cout << mTag << "Read[" << read_size << "]\n";
        return read_size;
    }

    /**
     @brief Write data to the BIO.
     @param in The buffer containing the data to be written.
     @param size The number of bytes to write.
     @return The number of bytes written to the BIO.
     */
    int write(const char *in, int size)
    {
        std::cout << mTag << "Waiting to write\n";
        auto lock = std::lock_guard(mData.mSignal.GetMutex());
        std::cout << mTag << "Write[" << size << "]\n";
        auto write_size = std::min(size, static_cast<int>(mData.mBuffer.available()));
        std::copy(in,
                  in + write_size,
                  mData.mBuffer.allocate_tail(static_cast<std::size_t>(write_size)).begin());
        mData.mSignal.Notify();
        return write_size;
    }

    /**
     @brief Handle control operations on the BIO.
     @param cmd The control command to be executed.
     @param larg A long value associated with the control command.
     @param parg A pointer associated with the control command.
     @return The result of the control operation.
     */
    long ctrl(int cmd, long larg, void *parg)
    {
        if (cmd == BIO_CTRL_FLUSH)
            return 1;
        return 0;
    }

    /**
     @brief Write a null-terminated string to the BIO.
     @param str The string to write.
     @return The number of bytes written.
     */
    int puts(const char *str)
    {
        return write(str, static_cast<int>(strlen(str)));
    }

    /**
     @brief Private constructor - only Base::make() can call it.
     @param tag A tag string for identifying the BIO instance.
     @param s A reference to the SyncBuffer object to be used by the BIO.
     */
    CtxTestBioType(const char *tag, SyncBuffer &s)
        : Base(), mTag(tag), mData(s)
    {
    }

    const char *mTag;  /**< A tag string for identifying the BIO instance. */
    SyncBuffer &mData; /**< A reference to the SyncBuffer object used by the BIO. */
};

static SyncBuffer srv_out;
static SyncBuffer cli_out;

TEST(SslContextTestSuite, create)
{
    SslContext ssl_ctx(MakeSslServerContext(SSLv23_method(), "cert.pem", "pvtkey.pem"));
}

int ClientConnect()
{
    SslContext ssl_ctx_cli(MakeSslClientContext(SSLv23_method(), "cert.pem"));
    SslSslBio ssl_cli(ssl_ctx_cli,
                      CtxTestBioType("Client In: ", srv_out),
                      CtxTestBioType("Client Out: ", cli_out));

    SSL_set_verify(ssl_cli.Get(), SSL_VERIFY_PEER, nullptr);
    SSL_set_verify_depth(ssl_cli.Get(), 4);
    auto ret = ssl_cli.Connect();
    if (ret != 1)
    {
        std::cout << "Client error: " << SSL_get_error(ssl_cli.Get(), ret) << "\n";
    }
    else
        std::cout << "TLS client handshake complete!\n";
    return ret;
}

int ServerAccept()
{
    SslContext ssl_ctx_srv(MakeSslServerContext(SSLv23_method(), "cert.pem", "pvtkey.pem"));
    SslSslBio ssl_srv(ssl_ctx_srv,
                      CtxTestBioType("Server In: ", cli_out),
                      CtxTestBioType("Server Out: ", srv_out));

    auto ret = ssl_srv.Accept();
    if (ret != 1)
    {
        std::cout << "Server error: " << SSL_get_error(ssl_srv.Get(), ret) << "\n";
    }
    else
        std::cout << "TLS server handshake complete!\n";
    return ret;
}

TEST(SslContextTestSuite, tls_handshake)
{
    auto join = AutoThread<>(&ServerAccept);

    auto r_cli = ClientConnect();
    EXPECT_EQ(r_cli, 1);
}

// =============================================================================
// PEM-based certificate and key loading tests
// =============================================================================

// Test certificate PEM (self-signed, CN=test-peer-1)
constexpr std::string_view TEST_CERT_PEM = R"(-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUBngRPBFdtH3D9dn/eo+OA8Y2jxAwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLdGVzdC1wZWVyLTEwHhcNMjYwMjAxMDgyODQ5WhcNMjcw
MjAxMDgyODQ5WjAWMRQwEgYDVQQDDAt0ZXN0LXBlZXItMTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAJyIfRx9P/b0ii5DvI8vEiw6J7VryqXB0ZcRjMNm
KcNhzoj33PQnLo+693xdGfSad40cg92vtppS769ccRvtWyxpUsMtMSpAxmLSKh8N
5fhOH6HBVKXMmFYC6mkBEMhWZLhZL6ZMFmHa4jWq3tDHyG5FpauJzv1G8V+BNwoP
Atcy9HPmM52MhHKxr7Ei8c/uXQyk9/RN6sPcJL3DWsFh3mkAbpoIXUZE7awXl5mQ
btuEoMg/sXmLZCHXi9M021Q/nTFz0pr1Ok1nn/Jiw/SUXju5Q+8cUwPhTFv77zQK
9EB9TFv2b6jyhLhpYBNUxX7PPyBDvVAb8fNlc2WsmELTlT0CAwEAAaNTMFEwHQYD
VR0OBBYEFOz1vnpjIj5e0ZT6qWyavnmndf0VMB8GA1UdIwQYMBaAFOz1vnpjIj5e
0ZT6qWyavnmndf0VMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
ACH2aLjmHs67Sf0A4N+LXEknRStWPp+bavyUBxPQUro2FVtOG8bH6OWxch9nyR4u
iyR4n2W6kjvtMS7kBgyjNOA5zgewO/yGDifbz8Ogcs93gglXF+Cw69g8KFG9EUUI
a1DoSsC73vX3F1KfyGhQT4JnIp/x+uQ9JBUFD/r61FsLtejucLGRDQaRSY8CWf6+
Ai9RgJCjcAOp4wNKkLKxYcEWOY03wJFE+oI8GEf4OcPZqHmrkl1HpQ4MuUVSLa3x
dBxOhij+Ej+n/nVw41scdvrvt0H+uW4dut+mCwgtQuwTYDfr9v/FfBvtCk9WMSYN
5essooZvpWShrEYJ/UtHMIs=
-----END CERTIFICATE-----)";

// Matching private key for TEST_CERT_PEM
constexpr std::string_view TEST_KEY_PEM = R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCciH0cfT/29Iou
Q7yPLxIsOie1a8qlwdGXEYzDZinDYc6I99z0Jy6Puvd8XRn0mneNHIPdr7aaUu+v
XHEb7VssaVLDLTEqQMZi0iofDeX4Th+hwVSlzJhWAuppARDIVmS4WS+mTBZh2uI1
qt7Qx8huRaWric79RvFfgTcKDwLXMvRz5jOdjIRysa+xIvHP7l0MpPf0TerD3CS9
w1rBYd5pAG6aCF1GRO2sF5eZkG7bhKDIP7F5i2Qh14vTNNtUP50xc9Ka9TpNZ5/y
YsP0lF47uUPvHFMD4Uxb++80CvRAfUxb9m+o8oS4aWATVMV+zz8gQ71QG/HzZXNl
rJhC05U9AgMBAAECggEAGVyYoJDu4r9YJ1cM3zW57e1N1EXRM8BPHxH++1JX49IV
fRGpVhWZe8u6K3P0e4HjJJG2KXvG5AYyPpCf8W8bnY1NLJhqXFVPqLLPnrJBN0Ci
rDnJmPvQdq2fV0fPZ7/LY6OY7rp1z9Vs/bMPyHqZ98gN1GzGaKgX5Z9DZhI5QQXQ
7J3m+z+L5QXBKP5x5ZVDl5qV5hLQu2lPVLG0bVFpC4hNJYQ8Z7kL0F8xDPxeQPc1
3E8FQlEfSbpq1mJOqVLB7MWVQcP3/fCz8qmFnq4lTJnONH8Jz4JnJdEMK9m+5Y5f
rBQqbvQjE7VKQD1qI0dHpKS6vV7U9B5F9B5xvMNMdQKBgQDL1ZdXgHvVJxEQbF0W
KqvLpGw6X7a7LvFkWFqXE1LRx3TVQ8fX+kJT7f1B7iyE8F3cN9Y8bXxK4q0lM7rQ
6oXLxPGY7t3xbw3I2k5f6K3xO5nBPZQ3kFwfz7xqPEzMpW8nM0OJ4vQ6Y0CmF2I0
jMxyF5V8lJG9GfKFjmXJjQ2QZwKBgQDFmvfpJsG3d1oKZLJLvCJrQ6g0bFM5Lzpr
8nMF4ZWQP4FJX8w+NJBY2KmqWKEQQ1v0L5rG6GEJMq+S9cDnF2QRc8G3kvPVL0dQ
7qX7u+8rL5gN3n0fhM0y8sBEZ3MpW0dPvVrMGg3X0lJCMFX8NpuqPRL0cNQCM8Xz
OWJ4O0y8mwKBgQC3xqq3FY9p5qFE4JJbQpqvJ9xNJIxVi7CmQ3G5bfJD0fLmfUQL
bPRv6U8D9AWJZ0bMvvxCKP9FeVQ8rFHf0fANQVqL3eY1w0l6C7HfRLNy0cLuU9Qn
NFKZ3b7LVfKaZq7dX1Z8L6MXQ8kH7qI3fVqEZ8bnL3kfP3LqZyV7HQTQ2QKBgGGV
lxT8cvNQAVnL8L0+RP5C2i5fR3qX2QJNP9gQA1p7E8D9qKV6LcA2Pce+MXnVf0mC
aZ0dqL3mXV0qMLpWmrVLxN1bV0dT4BQFR4F5E9Pv3JDQF4OQLA8rVxP2Z7C0f5Qx
RpE3AX8mQH3fF5JG7r2ANLL3fQWE9qJQ3G7MWXyxAoGBAKJQQ+gqH1c0E9W3K8mE
3DPcLZ0dHVfK5YZQZ7HqVJ+E9K8bFNJ0L8F5Y7RQWF3c5nQ8c7L+XMGF9wL7J8LA
WL8VQ+QiP5e3F+Wv0K3c7mQFRZ0V5K3PJQE+mWxL3vY7E5cZW6F9JEb1lWRW7n8K
fMsQP9C8AiLq5K3Q7JwfVZ0g
-----END PRIVATE KEY-----)";

TEST(SslContextTestSuite, UseCertificatePem)
{
    SslContext ctx(TLS_server_method());
    EXPECT_NO_THROW(ctx.UseCertificatePem(TEST_CERT_PEM));
}

TEST(SslContextTestSuite, UsePrivateKeyPem)
{
    SslContext ctx(TLS_server_method());
    ctx.UseCertificatePem(TEST_CERT_PEM);
    EXPECT_NO_THROW(ctx.UsePrivateKeyPem(TEST_KEY_PEM));
}

TEST(SslContextTestSuite, UseCertificateAndKeyPem)
{
    SslContext ctx(TLS_server_method());
    ctx.UseCertificatePem(TEST_CERT_PEM);
    ctx.UsePrivateKeyPem(TEST_KEY_PEM);

    // Verify the key matches the certificate
    EXPECT_EQ(SSL_CTX_check_private_key(ctx.Get()), 1);
}

TEST(SslContextTestSuite, UseCertificatePemInvalidThrows)
{
    SslContext ctx(TLS_server_method());
    EXPECT_THROW(ctx.UseCertificatePem("not a valid pem"), SslException);
}

TEST(SslContextTestSuite, UsePrivateKeyPemInvalidThrows)
{
    SslContext ctx(TLS_server_method());
    EXPECT_THROW(ctx.UsePrivateKeyPem("not a valid pem"), SslException);
}

TEST(SslContextTestSuite, UseCertificateWithSslX509)
{
    SslContext ctx(TLS_server_method());
    SslX509 cert(TEST_CERT_PEM);
    EXPECT_NO_THROW(ctx.UseCertificate(cert));
}

TEST(SslContextTestSuite, UsePrivateKeyWithSslEvpKey)
{
    SslContext ctx(TLS_server_method());
    ctx.UseCertificatePem(TEST_CERT_PEM);
    SslEvpKey pkey(TEST_KEY_PEM);
    EXPECT_NO_THROW(ctx.UsePrivateKey(pkey));

    // Verify the key matches
    EXPECT_EQ(SSL_CTX_check_private_key(ctx.Get()), 1);
}
