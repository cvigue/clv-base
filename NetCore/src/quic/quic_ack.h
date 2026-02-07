// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <algorithm>
#include <cstdint>
#include <set>
#include <vector>

namespace clv::quic {

/// ACK range representation (RFC 9000 §19.3)
/// Represents a contiguous range of acknowledged packet numbers
struct AckRange
{
    std::uint64_t start{0}; // First packet number in range (inclusive)
    std::uint64_t end{0};   // Last packet number in range (inclusive)

    /// Check if this range contains a packet number
    [[nodiscard]] bool Contains(std::uint64_t pn) const noexcept
    {
        return pn >= start && pn <= end;
    }

    /// Get the number of packets in this range
    [[nodiscard]] std::uint64_t Count() const noexcept
    {
        return (end >= start) ? (end - start + 1) : 0;
    }

    /// Check if two ranges are adjacent (can be merged)
    [[nodiscard]] bool IsAdjacentTo(const AckRange &other) const noexcept
    {
        return (end + 1 == other.start) || (other.end + 1 == start);
    }

    /// Check if two ranges overlap
    [[nodiscard]] bool Overlaps(const AckRange &other) const noexcept
    {
        return !(end < other.start || start > other.end);
    }

    /// Merge with another range (assumes they overlap or are adjacent)
    [[nodiscard]] AckRange Merge(const AckRange &other) const noexcept
    {
        return AckRange{std::min(start, other.start), std::max(end, other.end)};
    }
};

/// Manages a set of ACK ranges efficiently
/// Maintains ranges in sorted order (highest to lowest) as per RFC 9000 §19.3
class AckRangeSet
{
  public:
    /// Add a packet number to the ACK set
    void AddPacketNumber(std::uint64_t pn) noexcept
    {
        // Try to extend existing range or create new one
        for (auto &range : ranges_)
        {
            // Check if we can extend this range
            if (pn == range.end + 1)
            {
                range.end = pn;
                MergeAdjacentRanges();
                return;
            }
            else if (pn == range.start - 1)
            {
                range.start = pn;
                MergeAdjacentRanges();
                return;
            }
            else if (range.Contains(pn))
            {
                // Already in range
                return;
            }
        }

        // Create new range
        ranges_.push_back(AckRange{pn, pn});
        SortAndMerge();
    }

    /// Add a range of packet numbers
    void AddRange(std::uint64_t start, std::uint64_t end) noexcept
    {
        if (end < start)
            return;

        ranges_.push_back(AckRange{start, end});
        SortAndMerge();
    }

    /// Check if a packet number is acknowledged
    [[nodiscard]] bool Contains(std::uint64_t pn) const noexcept
    {
        for (const auto &range : ranges_)
        {
            if (range.Contains(pn))
                return true;
        }
        return false;
    }

    /// Get the largest acknowledged packet number
    [[nodiscard]] std::uint64_t GetLargest() const noexcept
    {
        if (ranges_.empty())
            return 0;

        std::uint64_t largest = 0;
        for (const auto &range : ranges_)
        {
            largest = std::max(largest, range.end);
        }
        return largest;
    }

    /// Get all ranges (sorted descending by start)
    [[nodiscard]] const std::vector<AckRange> &GetRanges() const noexcept
    {
        return ranges_;
    }

    /// Get number of ranges
    [[nodiscard]] std::size_t RangeCount() const noexcept
    {
        return ranges_.size();
    }

    /// Get total number of acknowledged packets
    [[nodiscard]] std::uint64_t TotalCount() const noexcept
    {
        std::uint64_t count = 0;
        for (const auto &range : ranges_)
        {
            count += range.Count();
        }
        return count;
    }

    /// Clear all ranges
    void Clear() noexcept
    {
        ranges_.clear();
    }

    /// Build from a set of packet numbers
    static AckRangeSet FromPacketNumbers(const std::set<std::uint64_t> &packet_numbers) noexcept
    {
        AckRangeSet result;
        for (std::uint64_t pn : packet_numbers)
        {
            result.AddPacketNumber(pn);
        }
        return result;
    }

  private:
    std::vector<AckRange> ranges_;

    /// Sort ranges in descending order and merge overlapping/adjacent ranges
    void SortAndMerge() noexcept
    {
        if (ranges_.empty())
            return;

        // Sort by start (descending for wire format compatibility)
        std::sort(ranges_.begin(), ranges_.end(), [](const AckRange &a, const AckRange &b)
        { return a.start > b.start; });

        // Merge overlapping or adjacent ranges
        std::vector<AckRange> merged;
        merged.reserve(ranges_.size());
        merged.push_back(ranges_[0]);

        for (std::size_t i = 1; i < ranges_.size(); ++i)
        {
            auto &current = ranges_[i];
            auto &last = merged.back();

            if (last.Overlaps(current) || last.IsAdjacentTo(current))
            {
                last = last.Merge(current);
            }
            else
            {
                merged.push_back(current);
            }
        }

        ranges_ = std::move(merged);
    }

    /// Merge adjacent ranges (called after extending a range)
    void MergeAdjacentRanges() noexcept
    {
        if (ranges_.size() <= 1)
            return;

        for (std::size_t i = 0; i < ranges_.size() - 1; ++i)
        {
            for (std::size_t j = i + 1; j < ranges_.size(); ++j)
            {
                if (ranges_[i].IsAdjacentTo(ranges_[j]) || ranges_[i].Overlaps(ranges_[j]))
                {
                    ranges_[i] = ranges_[i].Merge(ranges_[j]);
                    ranges_.erase(ranges_.begin() + j);
                    --j;
                }
            }
        }
    }
};

} // namespace clv::quic
