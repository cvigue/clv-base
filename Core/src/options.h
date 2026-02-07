// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CORE_OPTIONS_H
#define CLV_CORE_OPTIONS_H

#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>
#include <functional>
#include <stdexcept>
#include <vector>

#include "intrinsic_type.h"

namespace clv {

/**
    @brief Holds the list of key/value options
    @struct Options

    The Options struct defines a data structure to hold command line options and their values.

    It takes in command line arguments (argc and argv) and a list of option specifications
    (SpecList) as inputs. It provides methods to add, access, and iterate over the options.
    The key methods are:

    - operator[] to access an option by key
    - Add to add a new option
    - Reset to initialize the options from command line args
    - ForEach to iterate through all options

    The main data member:

    OptionList - An unordered map holding the key-value pairs of options. It stores each option
    as a key-value pair in the OptionList map. The key is the option name string, and the value
    is an optional string for the value. To initialize, it parses the command line args based
    on the given SpecList. Each Spec defines the expected option name, if it's a flag, the key
    to store it under, default value, etc. It extracts the options from argv and stores them in
    the OptionList map.
*/
struct Options
{
    // Types
    struct Item;
    struct Spec;
    using value_type = std::optional<std::string>;
    using for_each_fn = std::function<void(std::string_view, const Item &)>;
    using SpecList = std::vector<Spec>;

  public: // Instance management
    Options() = default;
    Options(int ac, const char **av, SpecList) noexcept;

  public: // API
    Item operator[](const std::string &) noexcept;
    Options &Add(const std::string &key, const value_type &value = std::nullopt);
    Options &Reset(int ac, const char **av, const SpecList &tags);
    const Options &ForEach(for_each_fn) const noexcept;
    template <typename OutStreamT>
    void EmitHints(OutStreamT &,
                   const SpecList &tags,
                   std::size_t indentDepth = 4);

  private: // Private types
    using OptionList = std::unordered_map<std::string, value_type>;
    using CmdList = std::vector<std::string>;

  private: // Helpers
    void AddFromIter(const Options::Spec &spec, CmdList &cmdArgs, CmdList::iterator found);

  private: // Data
    OptionList mOptions;
    static inline value_type mNotFound = std::nullopt;
};

/**
    @brief Specifies the expectations of the arguments for Options
    @struct Options::Spec
    @details  used to define the specification for a command-line option or flag. It
    encapsulates the information needed to describe an option, including its name(s), help
    text, whether it is a flag (boolean option) or takes a value, the key used to identify
    the option, and an optional default value.

    Here's a breakdown of the members and constructors:

    Name struct:

        This nested struct holds the long and short names for an option.
        mLong is a std::string representing the long name of the option (e.g., "--verbose").
        mShort is an std::optional<char> representing the short name of the option (e.g., 'v').

    mTag member:

        This std::variant member can hold either an int or a Name struct.
        The int value is used when constructing the Spec with an index (for positional arguments).
        The Name struct is used when constructing the Spec with long and short option names.

    mHelpText member:

        A std::string that holds the help text or description for the option.

    mIsFlag member:

       A bool indicating whether the option is a flag (boolean option) or takes a value.

    mKey member:

        A std::string representing the key used to identify the option in the parsed options map.

    mValue member:

        An std::optional<std::string> that holds the default value for the option, if provided.

    The Options::Spec struct is used to define the specifications for command-line options
    and flags, which are then used by the Options class to parse the command-line
    arguments and provide a convenient interface for accessing the parsed options and
    their values.
*/
struct Options::Spec
{
    struct Name
    {
        std::string mLong;
        std::optional<char> mShort;
    };

    Spec(int index,
         std::string help,
         bool isFlag,
         std::string key,
         std::optional<std::string> defVal = std::nullopt);

    Spec(std::string long_tag,
         std::optional<char> short_tag,
         std::string help,
         bool isFlag,
         std::string key,
         std::optional<std::string> defVal = std::nullopt);

    std::variant<int, Name> mTag;
    std::string mHelpText = "";
    bool mIsFlag = false;
    std::string mKey;
    std::optional<std::string> mValue;
};
/**
    @brief Construct a new Options::Spec object with an index and optional default value
    @param index Position in the command line to expect the argument
    @param help Help text that can be provided
    @param isFlag True if this argument is a simple flag with no trailing parameter expected
    @param key The internal key that will be associated with this argument
    @param defVal Optional default value. Adding this makes the argument optional.
*/
inline Options::Spec::Spec(int index,
                           std::string help,
                           bool isFlag,
                           std::string key,
                           std::optional<std::string> defVal)
    : mTag(index),
      mHelpText(help),
      mIsFlag(isFlag),
      mKey(key),
      mValue(defVal) {};
/**
    @brief Construct a new Options::Spec object with a name, an optional short name, and an optional default value
    @param long_tag Long option name string, will have '--' prepended before it's searched for
    @param short_tag Short option shortcut character, will have '-' prepended before it's searched for
    @param help Help text that can be provided
    @param isFlag True if this argument is a simple flag with no trailing parameter expected
    @param key The internal key that will be associated with this argument
    @param defVal Optional default value. Adding this makes the argument optional.
*/
inline Options::Spec::Spec(std::string long_tag,
                           std::optional<char> short_tag,
                           std::string help,
                           bool isFlag,
                           std::string key,
                           std::optional<std::string> defVal)
    : mTag(Name{long_tag, short_tag}),
      mHelpText(help),
      mIsFlag(isFlag),
      mKey(key),
      mValue(defVal) {};

/**
    @brief An option item

    Returned in response to a call to Options::operator[], this type acts as an accessor to the entries
    within the Options instance. It includes functions to query whether the requested entry exists, has
    a value associated with it, and ways to convert that value to various useful types such as numbers
    or strings.
 */
struct Options::Item
{
    explicit Item(const value_type &) noexcept;

    bool Exists() const noexcept;
    bool HasValue() const noexcept;
    template <typename TypeT>
    auto get() const;
    template <typename TypeT>
    const auto &get(const TypeT &) const noexcept;
    template <typename TypeT>
    auto get(TypeT &&) const noexcept;

  private:
    const value_type &mValue;
};

/**
    @brief Construct a new Options object from the command line args to main()
    @param ac Command line arg count
    @param av Command line arg vector
    @param spec Structure specifying what arguments to expect
 */
inline Options::Options(int ac, const char **av, SpecList spec) noexcept
{
    Reset(ac, av, spec);
}
/**
    @brief Find the given value in the options list and return anItem encapsulating the result
    @param key key string to search for
    @return Options::Item result object

    Always returns an object of type Options::Item. The returned object will be in one of the three
    following states:

    - Key not found. The object will return false for 'Exists' and 'HasValue', and will throw if 'get' is called.
    - Key found with no value assigned. Object will return true for 'Exists', false for 'HasValue' and throws for 'get'.
    - Key found and value assigned. Returns true for 'Exists'/'HasValue' and will return a value for 'get'. The value
     might be nonsense if the wrong type is specified for get.
 */
inline Options::Item Options::operator[](const std::string &key) noexcept
{
    if (auto &&found = mOptions.find(key); found == mOptions.end())
        return Item(mNotFound);
    else
        return Item(found->second);
}
/**
    @brief Adds the specified key/value pair to the list
    @param key   key to be added
    @param value optional value to assign to the key.
    @return Options& fluent interface reference

    Adds the specified key/value pair to the list, existing keys can be modified.
 */
inline Options &Options::Add(const std::string &key, const value_type &value)
{
    if (key != "")
        mOptions[key] = value;
    return *this;
}
/**
    @brief Adds keys and values to the list from the command line args
    @param ac   Command line arg count
    @param av   Command line arg vector
    @param specs Structure specifying what arguments to expect
    @return Options& fluent interface reference
    @details  initializes and populates the options list from the command-line arguments provided
    to the program.

    It takes three inputs:

    ac (argument count): The number of command-line arguments passed to the program.
    av (argument vector): An array of C-style strings containing the command-line arguments.
    specs: A list of option specifications that define the expected options and their properties.
    The function's purpose is to parse the command-line arguments based on the provided
    specifications and store the extracted options and their values in the mOptions data
    member, which is an unordered map.

    Here's how the function achieves its purpose:

    It first clears the existing mOptions map to start fresh then creates a vector cmdArgs and
    populates it with the command-line arguments from av. It iterates over each option
    specification in specs and for each specification, it checks if the option is a positional
    argument (identified by an index) or a named argument (identified by a long or short name).

    If the option is a positional argument, it retrieves the corresponding value from cmdArgs
    based on the index and adds it to mOptions using the specified key.

    If the option is a named argument, it searches for the long or short name in cmdArgs. If
    found, it retrieves the corresponding value (if any) and adds it to mOptions using the
    specified key.

    If a required option is not found in cmdArgs and a default value is provided in the
    specification, it adds the default value to mOptions.

    If a required option is not found and no default value is provided, it throws a runtime error.
    After processing all specifications, it checks if there are any unused command-line arguments
    left in cmdArgs. If so, it throws a runtime error.
    Finally, it checks if any required options are missing from mOptions and throws a runtime
    error if any are missing.

    The function performs data transformations by converting the command-line arguments from av
    into a vector of strings (cmdArgs), and then extracting the options and their values from
    cmdArgs based on the provided specifications, storing them in the mOptions map.

    The main logic flow involves iterating over the option specifications, searching for the
    corresponding options in cmdArgs, and adding the found options and their values to
    mOptions. It also handles various error cases, such as missing required options or
    unexpected command-line arguments.
*/
inline Options &Options::Reset(int ac, const char **av, const SpecList &specs)
{
    mOptions.clear();
    CmdList cmdArgs;
    for (auto i = int(0); i < ac; ++i)
    {
        cmdArgs.emplace_back(av[i]);
    }

    auto removedArgs = int(0);

    for (auto &&optSpec : specs)
    {
        if (std::holds_alternative<int>(optSpec.mTag))
        {
            auto index = static_cast<std::size_t>(std::get<int>(optSpec.mTag) - removedArgs);
            if (index < cmdArgs.size())
            {
                Add(optSpec.mKey, cmdArgs[index]);
                cmdArgs.erase(std::next(cmdArgs.begin(), index));
                ++removedArgs;
            }
            else if (optSpec.mValue)
            {
                Add(optSpec.mKey, *optSpec.mValue);
            }
            else
                throw std::runtime_error("Expected argument location is out of range");
        }
        else // Named arg
        {
            auto &tag = std::get<Spec::Name>(optSpec.mTag);
            auto found = std::find_if(cmdArgs.begin(), cmdArgs.end(), [&name = tag.mLong](auto &&cmdArg)
            { return cmdArg == "--" + name; });

            if (found != cmdArgs.end())
            {
                auto &tag = std::get<Spec::Name>(optSpec.mTag);
                auto found = std::find_if(cmdArgs.begin(), cmdArgs.end(), [&name = tag.mLong](auto &&cmdArg)
                { return cmdArg == "--" + name; });
                AddFromIter(optSpec, cmdArgs, found);
            }
            else if (tag.mShort)
            {
                auto name = std::string("-") + std::string(1, *tag.mShort);
                found = std::find_if(cmdArgs.begin(), cmdArgs.end(), [&name](auto &&cmdArg)
                { return cmdArg == name; });
                if (found != cmdArgs.end())
                    AddFromIter(optSpec, cmdArgs, found);
                else if (optSpec.mValue)
                    Add(optSpec.mKey, *optSpec.mValue);
            }
            else if (optSpec.mValue)
            {
                Add(optSpec.mKey, *optSpec.mValue);
            }
            else
                throw std::runtime_error("Required argument missing: " + optSpec.mKey);
        }
    }

    // Test for unused cmdline entities
    if (cmdArgs.empty() == false)
        throw std::runtime_error("Unexpected input on command line");

    // Check for missing args
    for (auto &&optSpec : specs)
    {
        if (!this->operator[](optSpec.mKey).Exists())
            throw std::runtime_error("Missing required input on command line: " + optSpec.mKey);
    }

    return *this;
}
/**
    @brief Perform the given operation on each entry in the list
    @param cb Callback function, called for each item
    @return Options& fluent interface reference
 */
inline const Options &Options::ForEach(for_each_fn cb) const noexcept
{
    for (const auto &item : mOptions)
    {
        cb(item.first, Item(item.second));
    }
    return *this;
}

/**
    @brief Send formatted hints to the specified stream.
    @tparam StreamT Stream type
    @param out Instance of the stream
    @todo Generate help for indexed arguments
    @todo Format long lines prettier
*/
template <typename StreamT>
inline void Options::EmitHints(StreamT &out, const SpecList &tags, std::size_t indentDepth)
{
    // Compute max name length
    auto maxLen = size_t(0);
    for (auto &&tag : tags)
    {
        if (std::holds_alternative<Spec::Name>(tag.mTag))
        {
            auto tagName = std::get<Spec::Name>(tag.mTag);
            // Add space for '--', plus '-' and a space between if short is present
            auto tagLen = tagName.mLong.size() + 2 + (tagName.mShort ? size_t(3) : size_t(0));
            maxLen = std::max(maxLen, tagLen);
        }
    }

    for (auto &&tag : tags)
    {
        if (!tag.mHelpText.empty() && std::holds_alternative<Spec::Name>(tag.mTag))
        {
            auto tagName = std::get<Spec::Name>(tag.mTag);
            auto tagText = "--" + tagName.mLong;
            if (tagName.mShort)
            {
                tagText.append(" -");
                tagText.append(1, *tagName.mShort);
            }

            auto gap = maxLen - tagText.size();
            out << std::string(indentDepth, ' ') << tagText
                << ": " << std::string(gap, ' ') << tag.mHelpText << "\n";
        }
    }
}

/** @brief Adds an option value from the command line arguments iterator.
    @tparam Spec The specification of the option to add.
    @tparam CmdList The list of command line arguments.
    @param spec The specification of the option to add.
    @param cmdArgs The list of command line arguments.
    @param found The iterator pointing to the option key in the command line arguments.
    @throws std::runtime_error If the required argument value location is out of range.
 */
inline void Options::AddFromIter(const Options::Spec &spec, CmdList &cmdArgs, CmdList::iterator found)
{
    if (spec.mIsFlag)
    {
        Add(spec.mKey, std::nullopt);
        cmdArgs.erase(found);
    }
    else if (std::next(found) != cmdArgs.end())
    {
        Add(spec.mKey, *std::next(found));
        cmdArgs.erase(found, std::next(found, 2));
    }
    else
        throw std::runtime_error("Required argument value location is out of range");
}

/** @brief Constructs an Item object with the given value.
    @tparam value_type The type of the value to be stored in the Item.
    @param value The value to be stored in the Item.
 */
inline Options::Item::Item(const value_type &value) noexcept
    : mValue(value)
{
}

/** @brief Checks if the Item has a value.
    @return True if the Item has a value, false otherwise.
 */
inline bool Options::Item::Exists() const noexcept
{
    return &mValue != &mNotFound;
}

/** @brief Checks if the Item has a stored value.
    @return True if the Item has a stored value, false otherwise.
 */
inline bool Options::Item::HasValue() const noexcept
{
    return Exists() && mValue.has_value();
}
/**
    @brief Get the value associated with this item
    @tparam TypeT Desired result type
    @return auto Value converted to the desired type

    Tries to convert the value stored in this item to the specified type. The result may be nonsense
    but the type should be correct. If no value is present runtime_error exception is thrown.
 */
template <typename TypeT>
auto Options::Item::get() const
{
    if (HasValue())
    {
        if constexpr (std::is_same_v<bool, TypeT>)
            return *mValue == "1" || *mValue == "true";
        else if constexpr (std::is_same_v<int, TypeT>)
            return std::stoi(*mValue);
        else if constexpr (std::is_same_v<long, TypeT>)
            return std::stol(*mValue);
        else if constexpr (std::is_same_v<float, TypeT>)
            return std::stof(*mValue);
        else if constexpr (std::is_same_v<double, TypeT>)
            return std::stod(*mValue);
        else
            return *mValue;
    }
    throw std::runtime_error("Item::get<>() called with empty value");
}
/**
    @brief Get the value associated with this item
    @tparam TypeT Desired result type
    @param defVal Default value that should be used if no value is found
    @return auto Value converted to the desired type

    Tries to convert the value stored in this item to the specified type. The result may be nonsense
    but the type should be correct. If no value is present the given default is returned.
 */
template <typename TypeT>
const auto &Options::Item::get(const TypeT &defVal) const noexcept
{
    if (HasValue())
        return get<TypeT>();
    else
        return defVal;
}
template <typename TypeT>
auto Options::Item::get(TypeT &&defVal) const noexcept
{
    if (HasValue())
        return get<TypeT>();
    else
        return defVal;
}

} // namespace clv

#endif // CLV_CORE_OPTIONS_H
