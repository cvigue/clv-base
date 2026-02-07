// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSLX509_H
#define CLV_SSLHELP_SSLX509_H

#include <cstddef>
#include <cstdio>
#include <initializer_list>
#include <istream>
#include <iterator>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/safestack.h>
#include <openssl/types.h>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <chrono>
#include <filesystem>

#include "HelpSslException.h"
#include "HelpSslWithRc.h"
#include "HelpSslBio.h"
#include "HelpSslAsn1.h"
#include "HelpSslX509Name.h"
#include "HelpSslX509StoreCtx.h"
#include "HelpSslFileUtils.h"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>


namespace clv::OpenSSL {

/// Convert human-readable X.509 version (1, 2, 3) to OpenSSL's 0-based encoding
constexpr long X509Version(long v)
{
    return v - 1;
}

/**
    @brief Wraps an OpenSSL X509 in a C++ RAII wrapper
    @details The SslX509 struct is a wrapper around the OpenSSL X509 structure, which represents an
    X.509 certificate. It inherits from the SslWithRc class, which provides reference counting and
    memory management for the underlying X509 object.
*/
struct SslX509 : SslWithRc<X509, &X509_new, &X509_free, &X509_up_ref>
{
    using SslWithRc<X509, &X509_new, &X509_free, &X509_up_ref>::SslWithRc;
    SslX509(std::string_view buffer);
    SslX509(std::istream &&s);
    SslX509(SslX509 &ca, SslX509 &donor, std::string_view domainName);

    void SetSerialNumber(SslAsn1Integer &&);
    SslAsn1Integer GetSerialNumber();
    void SetIssuerName(const SslX509Name &);
    SslX509Name GetIssuerName();
    void SetSubjectName(const SslX509Name &);
    SslX509Name GetSubjectName();

    std::string GetPEM();
    void PemRead(std::istream &&s);

    // Certificate validation methods
    bool IsValidAtTime(std::chrono::system_clock::time_point time = std::chrono::system_clock::now()) const;
    bool VerifySignature(const SslX509 &issuer_cert) const;
    bool HasKeyUsage(int usage_flag) const;
    bool HasExtendedKeyUsage(int nid) const;
    std::string GetCommonName() const;
    std::vector<std::string> GetSubjectAlternativeNames() const;
    std::string GetFingerprint(const EVP_MD *md = EVP_sha256()) const;
    bool MatchesPeerIdentity(const std::string &expected_id) const;
    std::optional<std::string> GetExtensionValue(int nid) const;
    bool IsCA() const;
    std::optional<int> GetPathLengthConstraint() const;

    // Static validation helpers
    static bool VerifyChain(const SslX509 &cert, const std::vector<SslX509> &chain, X509_STORE *trust_store);
    static std::vector<SslX509> LoadChainFromFile(const std::filesystem::path &file);

    /**
        @brief Create an SslX509 from an external reference (bumps refcount)
        @param cert Raw X509 pointer (e.g., from X509_STORE_CTX)
        @return SslX509 that owns a reference
        @note Uses SslWithRc::BorrowRef; increments refcount before wrapping
    */
    static SslX509 Borrow(X509 *cert)
    {
        return SslWithRc::BorrowRef<SslX509>(cert);
    }

  private:
    void CopySelectedExtensions(SslX509 src, std::initializer_list<int> selected);
};
/**
  @brief Construct a new SslX509 object from a PEM string
  @param buffer PEM data
*/
inline SslX509::SslX509(std::string_view buffer)
    : SslX509()
{
    SslBio bio(BIO_new_mem_buf(buffer.data(), -1));
    bio.ThrowIfNull("BIO_new_mem_buf failed");
    auto cert = PEM_read_bio_X509(bio.Get(), nullptr, nullptr, nullptr);
    if (!cert)
        throw SslException("PEM_read_bio_X509 failed");
    *this = SslX509(cert);
}
/**
  @brief Construct a new SslX509 object from a PEM stream
  @param buffer PEM data
*/
inline SslX509::SslX509(std::istream &&s)
    : SslX509(std::string(std::istreambuf_iterator<char>(s), {})) {};

/**
   @brief Creates a new X509 object and initializes it with the supplied parameters

   See: https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl

   Mostly useful for MitM inspection and other cert forging type deals.

   @param ca         X509 CA used to create the certificate.
   @param donor      X509 info donor cert
   @param domainName Target DN based on the connection request we're processing
   @todo info has an entry for Alt, use it or lose it
*/
inline SslX509::SslX509(SslX509 &ca,
                        SslX509 &donor,
                        std::string_view domainName)
    : SslX509()
{
    X509_set_version(Get(), X509Version(3));

    // TODO: How to check for errors here?
    X509_gmtime_adj(X509_get_notBefore(Get()), 0);
    X509_gmtime_adj(X509_get_notAfter(Get()), (14400));

    CopySelectedExtensions(donor, {NID_key_usage, NID_ext_key_usage, NID_subject_alt_name});
    SetIssuerName(ca.GetIssuerName());
    SetSubjectName(SslX509Name({{"CN", domainName}}));
    SetSerialNumber(SslAsn1Integer::Random64());
}
/**
    @brief Set cert serial via X509_set_serialNumber
    @param sn 64 bit serial number
*/
inline void SslX509::SetSerialNumber(SslAsn1Integer &&sn)
{
    if (X509_set_serialNumber(Get(), sn.Get()) != 1)
        throw SslException("X509_set_serialNumber failed");
}
/**
    @brief Return cert serial in ASN1 number wrapper
    @return SslAsn1Integer cert serial number
*/
inline SslAsn1Integer SslX509::GetSerialNumber()
{
    auto *serial = X509_get_serialNumber(Get());
    if (!serial)
        throw SslException("X509_get_serialNumber failed");
    return SslAsn1Integer(ASN1_INTEGER_dup(serial));
}
/**
   @brief Copies the selected list of X509 extensions to the dest cert from the src cert
   @param dest      Destination cert where the extensions will get copied into.
   @param src       Donor cert from which the extensions will be copied
   @param selected  List of NIDs to try to copy
*/
inline void SslX509::CopySelectedExtensions(SslX509 src, std::initializer_list<int> selected)
{
    auto extStack = X509_get0_extensions(src.Get());

    for (auto i = 0; sk_X509_EXTENSION_num(extStack) > i; ++i)
    {
        auto ext = sk_X509_EXTENSION_value(extStack, i);
        if (ext != nullptr)
        {
            auto object = X509_EXTENSION_get_object(ext);
            auto type = OBJ_obj2nid(object);
            for (auto nid : selected)
            {
                if (type == nid)
                {
                    if (X509_add_ext(Get(), ext, -1) != 1)
                        throw SslException("X509_add_ext failed");
                }
            }
        }
    }
}
/**
    @brief Set issuer name field with X509_set_issuer_name
    @param issuer desired name
*/
inline void SslX509::SetIssuerName(const SslX509Name &issuer)
{
    if (X509_set_issuer_name(Get(), issuer.Get()) != 1)
        throw SslException("X509_set_issuer_name failed");
}
/**
    @brief Set subject name field with X509_set_subject_name
    @param issuer desired name
*/
inline void SslX509::SetSubjectName(const SslX509Name &subject)
{
    if (X509_set_subject_name(Get(), subject.Get()) != 1)
        throw SslException("X509_set_subject_name failed");
}
/**
    @brief Get issuer name via X509_get_issuer_name
    @return SslX509Name Issuer name
*/
inline SslX509Name SslX509::GetIssuerName()
{
    auto *name = X509_get_issuer_name(Get());
    if (!name)
        throw SslException("X509_get_issuer_name failed");
    return SslX509Name(X509_NAME_dup(name));
}
/**
    @brief Get subject name via X509_get_subject_name
    @return SslX509Name Subject name
*/
inline SslX509Name SslX509::GetSubjectName()
{
    auto *name = X509_get_subject_name(Get());
    if (!name)
        throw SslException("X509_get_subject_name failed");
    return SslX509Name(X509_NAME_dup(name));
}
/**
    @brief Export cert as PEM string
    @return std::string the PEM data
*/
inline std::string SslX509::GetPEM()
{
    auto bio = SslBio(BIO_s_mem());
    PEM_write_bio_X509(bio.Get(), Get());
    char *data;
    size_t len = BIO_get_mem_data(bio.Get(), &data);
    return {data, len};
}

inline void SslX509::PemRead(std::istream &&s)
{
    // The string must outlive the BIO — BIO_new_mem_buf wraps without copying.
    auto pemData = std::string(std::istreambuf_iterator<char>(s), {});
    auto bio = SslBio(BIO_new_mem_buf(pemData.data(), -1));
    auto cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert)
        throw SslException("PEM_read_bio_X509 failed");
    *this = SslX509(cert);
}

/**
    @brief Check if certificate is valid at the given time
    @param time Time point to check (defaults to now)
    @return true if certificate is currently valid (notBefore <= time <= notAfter)
*/
inline bool SslX509::IsValidAtTime(std::chrono::system_clock::time_point time) const
{
    auto time_t_value = std::chrono::system_clock::to_time_t(time);

    const ASN1_TIME *not_before = X509_get0_notBefore(Get());
    const ASN1_TIME *not_after = X509_get0_notAfter(Get());

    if (!not_before || !not_after)
        return false;

    // Check if current time is after notBefore
    if (X509_cmp_time(not_before, &time_t_value) >= 0)
        return false;

    // Check if current time is before notAfter
    if (X509_cmp_time(not_after, &time_t_value) <= 0)
        return false;

    return true;
}

/**
    @brief Verify this certificate was signed by the issuer certificate
    @param issuer_cert The issuer's certificate
    @return true if signature is valid
*/
inline bool SslX509::VerifySignature(const SslX509 &issuer_cert) const
{
    EVP_PKEY *issuer_key = X509_get0_pubkey(issuer_cert.Get());
    if (!issuer_key)
        return false;

    int result = X509_verify(const_cast<X509 *>(Get()), issuer_key);
    return result == 1;
}

/**
    @brief Check if certificate has specific key usage
    @param usage_flag Key usage flag (e.g., KU_DIGITAL_SIGNATURE, KU_KEY_ENCIPHERMENT)
    @return true if the key usage is present
*/
inline bool SslX509::HasKeyUsage(int usage_flag) const
{
    auto usage = reinterpret_cast<ASN1_BIT_STRING *>(
        X509_get_ext_d2i(Get(), NID_key_usage, nullptr, nullptr));

    if (!usage)
        return false;

    // Wrap for RAII cleanup
    SslAsn1BitString usage_wrapped(usage);

    bool result = false;
    if (usage_flag < ASN1_STRING_length(usage_wrapped.Get()) * 8)
    {
        result = ASN1_BIT_STRING_get_bit(usage_wrapped.Get(), usage_flag) != 0;
    }

    return result;
}

/**
    @brief Check if certificate has extended key usage
    @param nid NID of extended key usage (e.g., NID_server_auth, NID_client_auth)
    @return true if the extended key usage is present
*/
inline bool SslX509::HasExtendedKeyUsage(int nid) const
{
    EXTENDED_KEY_USAGE *eku = static_cast<EXTENDED_KEY_USAGE *>(
        X509_get_ext_d2i(Get(), NID_ext_key_usage, nullptr, nullptr));

    if (!eku)
        return false;

    bool found = false;
    int num = sk_ASN1_OBJECT_num(eku);
    for (int i = 0; i < num; ++i)
    {
        ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(eku, i);
        if (OBJ_obj2nid(obj) == nid)
        {
            found = true;
            break;
        }
    }

    EXTENDED_KEY_USAGE_free(eku);
    return found;
}

/**
    @brief Get the Common Name (CN) from subject
    @return Common Name string, or empty if not found
*/
inline std::string SslX509::GetCommonName() const
{
    auto subject = X509_get_subject_name(Get());
    if (!subject)
        return "";

    int pos = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (pos == -1)
        return "";

    X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, pos);
    if (!entry)
        return "";

    ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
    if (!data)
        return "";

    unsigned char *utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&utf8, data);
    if (len < 0)
        return "";

    std::string result(reinterpret_cast<char *>(utf8), len);
    OPENSSL_free(utf8);
    return result;
}

/**
    @brief Get all Subject Alternative Names (SAN)
    @return Vector of SAN entries (DNS names and IP addresses as strings)
*/
inline std::vector<std::string> SslX509::GetSubjectAlternativeNames() const
{
    std::vector<std::string> san_list;

    GENERAL_NAMES *sans = static_cast<GENERAL_NAMES *>(
        X509_get_ext_d2i(Get(), NID_subject_alt_name, nullptr, nullptr));

    if (!sans)
        return san_list;

    int num_sans = sk_GENERAL_NAME_num(sans);
    for (int i = 0; i < num_sans; ++i)
    {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(sans, i);
        if (!gen)
            continue;

        if (gen->type == GEN_DNS)
        {
            ASN1_STRING *dns = gen->d.dNSName;
            unsigned char *utf8 = nullptr;
            int len = ASN1_STRING_to_UTF8(&utf8, dns);
            if (len >= 0)
            {
                san_list.emplace_back(reinterpret_cast<char *>(utf8), len);
                OPENSSL_free(utf8);
            }
        }
        else if (gen->type == GEN_IPADD)
        {
            ASN1_OCTET_STRING *ip = gen->d.iPAddress;
            const unsigned char *data = ASN1_STRING_get0_data(ip);
            int len = ASN1_STRING_length(ip);

            if (len == 4) // IPv4
            {
                char buf[16];
                snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);
                san_list.emplace_back(buf);
            }
            // TODO: Add IPv6 support if needed
        }
    }

    GENERAL_NAMES_free(sans);
    return san_list;
}

/**
    @brief Calculate certificate fingerprint
    @param md Message digest algorithm (default SHA256)
    @return Hex-encoded fingerprint
*/
inline std::string SslX509::GetFingerprint(const EVP_MD *md) const
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (X509_digest(Get(), md, digest, &digest_len) != 1)
        throw SslException("X509_digest failed");

    // Convert to hex string
    std::string result;
    result.reserve(digest_len * 2);

    for (unsigned int i = 0; i < digest_len; ++i)
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", digest[i]);
        result += hex;
    }

    return result;
}

/**
    @brief Check if certificate matches expected peer identity
    @param expected_id Expected CN or SAN
    @return true if CN or any SAN matches expected_id
*/
inline bool SslX509::MatchesPeerIdentity(const std::string &expected_id) const
{
    // Check CN
    if (GetCommonName() == expected_id)
        return true;

    // Check SANs
    auto sans = GetSubjectAlternativeNames();
    for (const auto &san : sans)
    {
        if (san == expected_id)
            return true;

        // Support simple wildcard matching for left-most label: "*.example.com"
        if (!san.empty() && san.size() > 2 && san[0] == '*' && san[1] == '.')
        {
            const std::string suffix = san.substr(1); // ".example.com"
            if (expected_id.size() > suffix.size() && expected_id.compare(expected_id.size() - suffix.size(), suffix.size(), suffix) == 0)
            {
                // Ensure there is a non-empty left-most label (prevent matching "example.com")
                size_t dot_pos = expected_id.find('.');
                if (dot_pos != std::string::npos && dot_pos > 0)
                    return true;
            }
        }
    }

    return false;
}

/**
    @brief Get extension value by NID
    @param nid Extension NID
    @return Extension value as string, or nullopt if not found
*/
inline std::optional<std::string> SslX509::GetExtensionValue(int nid) const
{
    int critical = 0;
    ASN1_OCTET_STRING *ext_data = static_cast<ASN1_OCTET_STRING *>(
        X509_get_ext_d2i(Get(), nid, &critical, nullptr));

    if (!ext_data)
        return std::nullopt;

    const unsigned char *data = ASN1_STRING_get0_data(ext_data);
    int len = ASN1_STRING_length(ext_data);

    std::string result(reinterpret_cast<const char *>(data), len);
    ASN1_OCTET_STRING_free(ext_data);

    return result;
}

/**
    @brief Check if certificate is a CA certificate
    @return true if certificate has CA:TRUE in basic constraints
*/
inline bool SslX509::IsCA() const
{
    auto bc_raw = reinterpret_cast<BASIC_CONSTRAINTS *>(
        X509_get_ext_d2i(Get(), NID_basic_constraints, nullptr, nullptr));

    if (!bc_raw)
        return false;

    // Wrap for RAII cleanup
    SslAsn1BasicConstraints bc(bc_raw);

    return bc.Get()->ca != 0;
}

/**
    @brief Get path length constraint from basic constraints
    @return Path length if present, nullopt otherwise
*/
inline std::optional<int> SslX509::GetPathLengthConstraint() const
{
    auto bc_raw = reinterpret_cast<BASIC_CONSTRAINTS *>(
        X509_get_ext_d2i(Get(), NID_basic_constraints, nullptr, nullptr));

    if (!bc_raw)
        return std::nullopt;

    // Wrap for RAII cleanup
    SslAsn1BasicConstraints bc(bc_raw);

    if (!bc.Get()->ca)
        return std::nullopt;

    std::optional<int> result;
    if (bc.Get()->pathlen)
        result = ASN1_INTEGER_get(bc.Get()->pathlen);

    return result;
}

/**
    @brief Verify certificate chain against trust store
    @param cert Certificate to verify
    @param chain Intermediate certificates (excluding root)
    @param trust_store X509_STORE with trusted root CAs
    @return true if chain is valid
*/
inline bool SslX509::VerifyChain(const SslX509 &cert, const std::vector<SslX509> &chain, X509_STORE *trust_store)
{
    if (!trust_store)
        return false;

    SslX509StoreCtx ctx;

    std::optional<SslX509Stack> chain_stack;
    STACK_OF(X509) *chain_ptr = nullptr;

    if (!chain.empty())
    {
        chain_stack.emplace();
        for (const auto &intermediate : chain)
        {
            // Need to cast away const for OpenSSL API
            chain_stack->Push(const_cast<X509 *>(intermediate.Get()));
        }
        chain_ptr = chain_stack->Raw();
    }

    if (!ctx.Init(trust_store, const_cast<X509 *>(cert.Get()), chain_ptr))
        return false;

    return ctx.Verify() == 1;
}

/**
    @brief Load certificate chain from PEM file
    @param file Path to PEM file containing one or more certificates
    @return Vector of certificates in order
*/
inline std::vector<SslX509> SslX509::LoadChainFromFile(const std::filesystem::path &file)
{
    std::vector<SslX509> chain;

    std::unique_ptr<FILE, decltype(&FileDeleter)> fp(fopen(file.string().c_str(), "r"), &FileDeleter);
    if (!fp)
        throw SslException("Failed to open certificate chain file");

    X509 *cert = nullptr;
    while ((cert = PEM_read_X509(fp.get(), nullptr, nullptr, nullptr)) != nullptr)
    {
        chain.emplace_back(cert);
    }

    if (chain.empty())
        throw SslException("No certificates found in chain file");

    return chain;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSLX509_H