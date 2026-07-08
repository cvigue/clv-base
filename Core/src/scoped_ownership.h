// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_SCOPED_OWNERSHIP_H
#define CLV_SCOPED_OWNERSHIP_H

namespace clv {

/**
 * @brief Move-only ownership flag shared by scoped kernel/proc guards.
 *
 * Tracks whether this guard instance acquired a resource that must be reverted
 * on destruction or move-assignment.
 */
class ScopedOwnership
{
  public:
    ScopedOwnership() = default;
    explicit ScopedOwnership(bool owns) noexcept
        : owns_(owns)
    {
    }

    ScopedOwnership(const ScopedOwnership &) = delete;
    ScopedOwnership &operator=(const ScopedOwnership &) = delete;

    ScopedOwnership(ScopedOwnership &&other) noexcept
        : owns_(other.owns_)
    {
        other.owns_ = false;
    }

    ScopedOwnership &operator=(ScopedOwnership &&other) noexcept
    {
        if (this != &other)
        {
            owns_ = other.owns_;
            other.owns_ = false;
        }
        return *this;
    }

    [[nodiscard]] bool owns() const noexcept
    {
        return owns_;
    }

    void set_owns(bool owns) noexcept
    {
        owns_ = owns;
    }

    void release() noexcept
    {
        owns_ = false;
    }

  private:
    bool owns_ = false;
};

} // namespace clv

#endif // CLV_SCOPED_OWNERSHIP_H
