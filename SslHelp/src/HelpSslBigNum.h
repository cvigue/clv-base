// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSL_BIG_NUM_H
#define CLV_SSLHELP_SSL_BIG_NUM_H

#include <limits>
#include <tuple>

#include "HelpSslException.h"
#include "HelpSslNoRc.h"

#include <openssl/bn.h>

namespace clv::OpenSSL {

/**
    @brief Utility alias for OpenSSL BN_CTX RAII wrapper
    @details
    Some BN (big number) operations require a 'context' object; this seems to be a sort of BN cache
    or something, but in any case it's sometimes needed. While it's best to create a BN_CTX and reuse
    it until the operations are done, it's not required to do so.

    From the OpenSSL docs:

    "A BN_CTX is a structure that holds BIGNUM temporary variables used by library functions. Since
    dynamic memory allocation to create BIGNUMs is rather expensive when used in conjunction with
    repeated subroutine calls, the BN_CTX structure is used."
    - https://www.openssl.org/docs/man1.1.1/man3/BN_CTX_new.html

    Some of the lower level math helpers expose the BN_CTX requirement to permit the suggested sort
    of BN_CTX reuse suggested above. There are also 'convenience' versions that take on the cost
    of allocating a BN_CTX every time. "You must choose, but choose wisely." - Indiana Jones

    This helper just provides a RAII wrapper to manage the lifespan of BN_CTX
*/
using SslBnContext = SslNoRc<BN_CTX, BN_CTX_new, BN_CTX_free>;
/**
    @brief CRTP base class for BigNum types, provides a set of BN ops for all (2) BN types
    @class SslBigNumOps
    @details
    Provides some basic operations on BN types and a framework for more operations as desired. Binary
    ops like +, -, *, etc are implemented as non-member functions below, as are some helpers that expose
    a little more of the BN internals in case more efficiency or complete results are needed.

    The motivation for taking on the slight complexity of CRTP for this is due to OpenSSL providing
    both secured and not-so-secured BN creation and disposal, with all other operations being the same.
    CRTP provides a nice OOP way to encapsulate this native functionality and share everything else.

    So to use, for example, a wrapped OpenSSL secure BN, all one would need to do is:

    auto bn = SslSecureBigNum(0);

    And then, because SslSecureBigNum derives from SslBigNumOps, the operations implemented for
    SslBigNumOps can be applied to 'bn' with no further fuss.

    @tparam BnT The BN type to enhance
*/
template <typename BnT>
struct SslBigNumOps
{
    explicit SslBigNumOps(uint64_t i = 0);

  public: // BN supplemental API
    auto Size() const noexcept;
    auto AsUint() const;
    void SetBit(int index);
    void ClrBit(int index);
    bool ChkBit(int index) const noexcept;
    auto &operator+=(const SslBigNumOps &rh);
    auto &operator-=(const SslBigNumOps &rh);
    auto &operator*=(const SslBigNumOps &rh);
    auto &operator/=(const SslBigNumOps &rh);

  public: // CRTP helpers
    auto &BN();
    const auto &BN() const;
};
// ================================================================================================
// Non-member helpers
// ================================================================================================
/**
    @brief Multiply two SslBigNumOps<> and return the result as a SslBigNumOps<>
    @tparam BnT A SslBigNumOps<> type
    @param lh left operand
    @param rh right operand
    @param ctx BN_CTX wrapper SslBnContext instance
    @return auto SslBigNumOps<> result
    @details The BN_CTX wrapper is exposed in case reuse is required for additional efficiency.
*/
template <typename BnT>
auto mul(const SslBigNumOps<BnT> &lh, const SslBigNumOps<BnT> &rh, SslBnContext &ctx)
{
    BnT r;
    if (BN_mul(r.BN(), lh.BN(), rh.BN(), ctx) != 1)
        throw SslException("BN_mul() exception");
    return r;
}
/**
    @brief Divide a SslBigNumOps<> by another SslBigNumOps<> and return the result as a tuple
    @tparam BnT A SslBigNumOps<> type
    @param lh left operand
    @param rh right operand
    @param ctx BN_CTX wrapper SslBnContext instance
    @return auto std::tuple<SslBigNumOps<>, SslBigNumOps<>> result
    @details The BN_CTX wrapper is exposed in case reuse is required for additional efficiency.
    Also, the return value is a tuple that contains the result of the division as the first member
    and the remainder as the second part.
*/
template <typename BnT>
auto div(const SslBigNumOps<BnT> &lh, const SslBigNumOps<BnT> &rh, SslBnContext &ctx)
{
    BnT r;
    BnT rem;
    if (BN_div(r.BN(), rem.BN(), lh.BN(), rh.BN(), ctx) != 1)
        throw SslException("BN_div() exception");
    return std::tuple(std::move(r), std::move(rem));
}
/**
    @brief Raise a SslBigNumOps<> by exponent SslBigNumOps<> and return the result
    @tparam BnT A SslBigNumOps<> type
    @param lh left operand
    @param rh right operand
    @param ctx BN_CTX wrapper SslBnContext instance
    @return auto SslBigNumOps<> result
    @details The BN_CTX wrapper is exposed in case reuse is required for additional efficiency.
*/
template <typename BnT>
auto pow(const SslBigNumOps<BnT> &a, const SslBigNumOps<BnT> &p, SslBnContext &ctx)
{
    BnT r;
    if (BN_exp(r.BN(), a.BN(), p.BN(), ctx) != 1)
        throw SslException("BN_exp() exception");
    return r;
}
/**
    @brief Raise a SslBigNumOps<> by exponent SslBigNumOps<> and return the result
    @tparam BnT A SslBigNumOps<> type
    @param lh left operand
    @param rh right operand
    @return auto SslBigNumOps<> result
    @details The BN_CTX wrapper is encapsulated for simplicity
*/
template <typename BnT>
auto pow(const SslBigNumOps<BnT> &a, const SslBigNumOps<BnT> &p)
{
    BnT r;
    SslBnContext ctx;
    return pow(a, p, ctx);
}
/**
    @brief Compare two SslBigNumOps<> and return the result
    @tparam BnT A SslBigNumOps<> type
    @param lh left operand
    @param rh right operand
    @return auto Returns the result of the BN_cmp OpenSSL function
*/
template <typename BnT>
auto cmp(const SslBigNumOps<BnT> &lh, const SslBigNumOps<BnT> &rh)
{
    return BN_cmp(lh.BN(), rh.BN());
}
// ================================================================================================
// Non-member Operators
// ================================================================================================
template <typename BnT>
auto operator==(const SslBigNumOps<BnT> &lh, const SslBigNumOps<BnT> &rh)
{
    return cmp(lh, rh) == 0;
}
template <typename BnT>
auto operator<=>(const SslBigNumOps<BnT> &lh, const SslBigNumOps<BnT> &rh)
{
    return cmp(lh, rh) <=> 0;
}
template <typename BnT>
auto operator+(const SslBigNumOps<BnT> &lh, const SslBigNumOps<BnT> &rh)
{
    BnT r;
    if (BN_add(r.BN(), lh.BN(), rh.BN()) != 1)
        throw SslException("BN_add() exception");
    return r;
}
template <typename BnT>
auto operator-(const SslBigNumOps<BnT> &lh, const SslBigNumOps<BnT> &rh)
{
    BnT r;
    if (BN_sub(r.BN(), lh.BN(), rh.BN()) != 1)
        throw SslException("BN_sub() exception");
    return r;
}
template <typename BnT>
auto operator*(const SslBigNumOps<BnT> &lh, const SslBigNumOps<BnT> &rh)
{
    BnT r;
    SslBnContext ctx; // TODO: if this is costly consider using a cache
    return mul(lh, rh, ctx);
}
template <typename BnT>
auto operator/(const SslBigNumOps<BnT> &lh, const SslBigNumOps<BnT> &rh)
{
    BnT r;
    SslBnContext ctx; // TODO: if this is costly consider using a cache
    auto [result, remainder] = div(lh, rh, ctx);
    return std::move(result);
}
template <typename BnT>
auto operator<<(const SslBigNumOps<BnT> &lh, const int shift)
{
    BnT r;
    if (BN_lshift(r.BN(), lh.BN(), shift) != 1)
        throw SslException("BN_lshift() exception");
    return r;
}
template <typename BnT>
auto operator>>(const SslBigNumOps<BnT> &lh, const int shift)
{
    BnT r;
    if (BN_rshift(r.BN(), lh.BN(), shift) != 1)
        throw SslException("BN_rshift() exception");
    return r;
}
// ================================================================================================
// SslBigNumOps Implementation
// ================================================================================================
/**
    @brief Construct a BN wrapper with the BN set to the given value
    @tparam BnT The SslBigNumOps derived type
    @param i Initializer
    @throws If the assignment or allocation fails.
*/
template <typename BnT>
SslBigNumOps<BnT>::SslBigNumOps(uint64_t i)
{
    if (BN_set_word(BN(), i) != 1)
        throw SslException("BN_set_word() failed");
}
/**
    @brief Return the number of bytes used in the BN to store the value.
    @tparam BnT The SslBigNumOps derived type
    @return auto Byte count
*/
template <typename BnT>
auto SslBigNumOps<BnT>::Size() const noexcept
{
    return BN_num_bytes(BN());
}
/**
    @brief Return the stored value as a BN_ULONG if possible
    @tparam BnT The SslBigNumOps derived type
    @return auto Value stored in the BN
    @throws If the conversion is not possible
*/
template <typename BnT>
auto SslBigNumOps<BnT>::AsUint() const
{
    if (auto result = BN_get_word(BN()); result != std::numeric_limits<BN_ULONG>::max())
        return result;
    throw SslException("BN_get_word conversion to BN_ULONG failed");
}
/**
    @brief Set the bit at the given offset
    @tparam BnT The SslBigNumOps derived type
    @param index The offset of the bit to be set
    @throws If the set operation fails
    @details If the index exceeds the size of the BN, the BN will expand
*/
template <typename BnT>
void SslBigNumOps<BnT>::SetBit(int index)
{
    if (BN_set_bit(BN(), index) != 1)
        throw SslException("BN_set_bit() failed");
}
/**
    @brief Clear the bit at the given offset
    @tparam BnT The SslBigNumOps derived type
    @param index The offset of the bit to be set
    @throws If the clear operation fails. Will fail if the index exceeds the size of the BN.
*/
template <typename BnT>
void SslBigNumOps<BnT>::ClrBit(int index)
{
    if (BN_clear_bit(BN(), index) != 1)
        throw SslException("BN_clear_bit() failed");
}
/**
    @brief Test the bit at the given offset
    @tparam BnT The SslBigNumOps derived type
    @param index The offset of the bit to be tested
    @return true If the bit was available for testing and was set
    @return false If bit is clear or could not be tested
*/
template <typename BnT>
bool SslBigNumOps<BnT>::ChkBit(int index) const noexcept
{
    return BN_is_bit_set(BN(), index) == 1;
}
/**
    @brief Add the given quantity to the BN
    @tparam BnT The SslBigNumOps derived type
    @param rh SslBigNumOps<> to be added
    @return auto& The altered SslBigNumOps<> derived type
*/
template <typename BnT>
auto &SslBigNumOps<BnT>::operator+=(const SslBigNumOps &rh)
{
    // Does not use helper above to avoid CTOR costs for temps
    if (BN_add(BN(), BN(), rh.BN()) != 1)
        throw SslException("BN_add() exception");
    return *this;
}
/**
    @brief Subtract the given quantity from the BN
    @tparam BnT The SslBigNumOps derived type
    @param rh SslBigNumOps<> to be subtracted
    @return auto& The altered SslBigNumOps<> derived type
*/
template <typename BnT>
auto &SslBigNumOps<BnT>::operator-=(const SslBigNumOps &rh)
{
    // Does not use helper above to avoid CTOR costs for temps
    if (BN_sub(BN(), BN(), rh.BN()) != 1)
        throw SslException("BN_sub() exception");
    return *this;
}
/**
    @brief Multiply the BN by the given quantity
    @tparam BnT The SslBigNumOps derived type
    @param rh SslBigNumOps<> to be used in the multiplication
    @return auto& The altered SslBigNumOps<> derived type
*/
template <typename BnT>
auto &SslBigNumOps<BnT>::operator*=(const SslBigNumOps &rh)
{
    // Does not use helper above to avoid CTOR costs for temps
    SslBnContext ctx; // TODO: if this is costly consider using a cache
    if (BN_mul(BN(), BN(), rh.BN(), ctx) != 1)
        throw SslException("BN_mul() exception");
    return *this;
}
/**
    @brief Divide the BN by the given quantity
    @tparam BnT The SslBigNumOps derived type
    @param rh SslBigNumOps<> to be used in the division
    @return auto& The altered SslBigNumOps<> derived type
    @details The division is done as usual for integers and the remainder is discarded
*/
template <typename BnT>
auto &SslBigNumOps<BnT>::operator/=(const SslBigNumOps &rh)
{
    // Does not use helper above to avoid CTOR costs for temps
    SslBnContext ctx; // TODO: if this is costly consider using a cache
    BnT rem;
    if (BN_div(BN(), rem.BN(), BN(), rh.BN(), ctx) != 1)
        throw SslException("BN_div() exception");
    return *this;
}
/**
    @brief CRTP helper to get a reference to the derived type
    @tparam BnT The SslBigNumOps derived type
    @return auto& Reference to the derived instance
*/
template <typename BnT>
auto &SslBigNumOps<BnT>::BN()
{
    return static_cast<BnT &>(*this);
}
/**
    @brief CRTP helper to get a reference to the derived type
    @tparam BnT The SslBigNumOps derived type
    @return auto& Reference to the derived instance
*/
template <typename BnT>
const auto &SslBigNumOps<BnT>::BN() const
{
    return static_cast<const BnT &>(*this);
}
// ================================================================================================
// OpenSSL BIGNUM types, base, plain and secured - can use the previous members, operators, helpers
// ================================================================================================
/**
    @brief OpenSSL BIGNUM RAII base class template
    @tparam BnAlloc
    @tparam BnFree
    @details This type inherits from SslNoRc for RAII-ification of the underlying type and from
    SslBigNumOps<> for the set of operations that are available. It only has one CTOR for the moment
    but if others are handy they can be added. The allocation and free functions are template
    arguments that the two BIGNUM classes below use to produce secured and not-secured varieties.
*/
template <auto BnAlloc, auto BnFree>
struct SslBigNumBase : SslNoRc<BIGNUM, BnAlloc, BnFree>, SslBigNumOps<SslBigNumBase<BnAlloc, BnFree>>
{
    explicit SslBigNumBase(uint64_t i = 0)
        : SslNoRc<BIGNUM, BnAlloc, BnFree>(), SslBigNumOps<SslBigNumBase<BnAlloc, BnFree>>(i) {};
};
/**
    @brief OpenSSL BIGNUM with no particular security measures
    @details This type inherits from SslBigNumBase and specifies 'normal' instantiation.
*/
using SslBigNum = SslBigNumBase<BN_new, BN_free>;
/**
    @brief OpenSSL BIGNUM which allocates on the OpenSSL secure heap and clears contents on exit
    @details This type inherits from SslBigNumBase and specifies 'secure' instantiation.

    It differs from SslBigNum in that it makes use of the OpenSSL BN_secure_new and BN_clear_free
    APIs which are advertised to provide enhanced security for secret numbers. This also helps
    prevent accidental leakage of secret numbers since SslBigNum and SslSecureBigNum mixed
    operations are not defined and should not compile.
*/
using SslSecureBigNum = SslBigNumBase<BN_secure_new, BN_clear_free>;

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_BIG_NUM_H
