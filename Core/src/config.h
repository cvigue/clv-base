// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_CONFIG_H
#define CLV_CONFIG_H

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <variant>
#include <stdexcept>
#include <utility>

namespace clv::config {

// Concept: T is one of the types in Ts pack
template <typename T, typename... Ts>
concept IsOneOf = (std::is_same_v<T, Ts> || ...);

/**
    @brief The core configuration value type - recursive variant
*/
template <typename... Ts>
struct ConfigValue
{
    using array_t = std::vector<ConfigValue<Ts...>>;
    using dict_t = std::unordered_map<std::string, ConfigValue<Ts...>>;
    using data_t = std::variant<std::monostate,
                                Ts...,
                                array_t,
                                dict_t>;
    data_t data;
};

// Sentinel value for "not found" - a monostate ConfigValue
template <typename... Ts>
inline static ConfigValue<Ts...> null_value{std::monostate{}};

/**
    @brief Accessor wrapper for ConfigValue
    ConfigItem provides safe type-checked access to ConfigValue.
    It holds a const reference to a ConfigValue owned by Config/Dict/Array.

    @tparam Ts Leaf value types
*/
template <typename... Ts>
class ConfigItem
{
  public:
    explicit ConfigItem(ConfigValue<Ts...> &val_ref) noexcept;
    explicit ConfigItem(const ConfigValue<Ts...> &val_ref) noexcept;

    ConfigItem(const ConfigItem &) noexcept = default;
    ConfigItem(ConfigItem &&) noexcept = default;
    ConfigItem &operator=(const ConfigItem &) noexcept = default;
    ConfigItem &operator=(ConfigItem &&) noexcept = default;
    ConfigItem &operator=(const ConfigValue<Ts...> &val_ref) noexcept;

    // Access object key
    ConfigItem operator[](const std::string &key) noexcept;
    const ConfigItem operator[](const std::string &key) const noexcept;

    // Access array index
    ConfigItem operator[](size_t index) noexcept;
    const ConfigItem operator[](size_t index) const noexcept;

    // Get value with type conversion
    template <typename TypeT>
    auto get() const;

    // Get with default fallback (by-value returns)
    template <typename TypeT>
    TypeT get(const TypeT &defVal) const noexcept;

    template <typename TypeT>
    TypeT get(TypeT &&defVal) const noexcept;

    template <typename TypeT>
    TypeT &ref();

    bool Exists() const noexcept;
    bool IsNull() const noexcept;
    bool IsObject() const noexcept;
    bool IsArray() const noexcept;

    template <typename TypeT>
    bool IsType() const noexcept;

    template <typename TypeT>
    bool Converts() const noexcept;

  private:
    auto &GetDictItem(const std::string &key) noexcept;
    auto &GetArrayItem(size_t index) noexcept;

  private:
    ConfigValue<Ts...> &mValue;
};

/**
    @brief Configuration container - root level dictionary
*/
template <typename... Ts>
class Config
{
  public:
    using dict_t = typename ConfigValue<Ts...>::dict_t;
    using array_t = typename ConfigValue<Ts...>::array_t;
    using item_t = ConfigItem<Ts...>;
    using value_type = ConfigValue<Ts...>;

    Config() = default;

    ConfigItem<Ts...> operator[](const std::string &key) noexcept;
    const ConfigItem<Ts...> operator[](const std::string &key) const noexcept;

    void Set(const std::string &key, const ConfigValue<Ts...> &value) noexcept;

    // Overloads for individual types using concept
    template <typename T>
        requires IsOneOf<T, Ts...>
    void Set(const std::string &key, const T &value) noexcept;

    bool HasKey(const std::string &key) const noexcept;
    size_t Size() const noexcept;

    template <typename FunctionT>
    void ForEach(FunctionT &&fn) const noexcept;

    void Clear() noexcept;

    dict_t &GetRoot() noexcept;

  private:
    dict_t mRoot;
};

// ============================================================================
// ConfigItem Inline Implementations
// ============================================================================

template <typename... Ts>
inline ConfigItem<Ts...>::ConfigItem(ConfigValue<Ts...> &val_ref) noexcept
    : mValue(val_ref)
{
}

template <typename... Ts>
inline ConfigItem<Ts...>::ConfigItem(const ConfigValue<Ts...> &val_ref) noexcept
    : mValue(const_cast<ConfigValue<Ts...> &>(val_ref))
{
}

template <typename... Ts>
inline auto ConfigItem<Ts...>::operator=(const ConfigValue<Ts...> &val_ref) noexcept -> ConfigItem &
{
    mValue = val_ref;
    return *this;
}

template <typename... Ts>
inline ConfigItem<Ts...> ConfigItem<Ts...>::operator[](const std::string &key) noexcept
{
    return ConfigItem(GetDictItem(key));
}

template <typename... Ts>
inline const ConfigItem<Ts...> ConfigItem<Ts...>::operator[](const std::string &key) const noexcept
{
    return ConfigItem(GetDictItem(key));
}

template <typename... Ts>
inline ConfigItem<Ts...> ConfigItem<Ts...>::operator[](size_t index) noexcept
{
    return ConfigItem(GetArrayItem(index));
}

template <typename... Ts>
inline const ConfigItem<Ts...> ConfigItem<Ts...>::operator[](size_t index) const noexcept
{
    return ConfigItem(std::as_const(*this).GetArrayItem(index));
}

template <typename... Ts>
template <typename TypeT>
inline auto ConfigItem<Ts...>::get() const
{
    // Direct type match
    if (auto *val = std::get_if<TypeT>(&mValue.data))
        return *val;

    // String conversions
    if (auto *str_ptr = std::get_if<std::string>(&mValue.data))
    {
        const auto &str = *str_ptr;

        if constexpr (std::is_same_v<bool, TypeT>)
            return str == "1" || str == "true" || str == "True" || str == "TRUE";
        else if constexpr (std::is_same_v<int, TypeT>)
            return std::stoi(str);
        else if constexpr (std::is_same_v<long, TypeT>)
            return std::stol(str);
        else if constexpr (std::is_same_v<long long, TypeT>)
            return std::stoll(str);
        else if constexpr (std::is_same_v<unsigned int, TypeT>)
            return static_cast<unsigned int>(std::stoul(str));
        else if constexpr (std::is_same_v<unsigned long, TypeT>)
            return std::stoul(str);
        else if constexpr (std::is_same_v<unsigned long long, TypeT>)
            return std::stoull(str);
        else if constexpr (std::is_same_v<float, TypeT>)
            return std::stof(str);
        else if constexpr (std::is_same_v<double, TypeT>)
            return std::stod(str);
        else if constexpr (std::is_same_v<std::string, TypeT>)
            return str;
    }

    throw std::runtime_error("ConfigItem::get() - type mismatch");
}

template <typename... Ts>
template <typename TypeT>
inline TypeT ConfigItem<Ts...>::get(const TypeT &defVal) const noexcept
{
    try // Since get() can try some conversions before it throws, this is acceptable
    {
        return get<TypeT>();
    }
    catch (const std::exception &)
    {
        return defVal;
    }
}

template <typename... Ts>
template <typename TypeT>
inline TypeT ConfigItem<Ts...>::get(TypeT &&defVal) const noexcept
{
    try // Since get() can try some conversions before it throws, this is acceptable
    {
        return get<TypeT>();
    }
    catch (const std::exception &)
    {
        return std::forward<TypeT>(defVal);
    }
}

template <typename... Ts>
template <typename TypeT>
inline TypeT &ConfigItem<Ts...>::ref()
{
    return std::get<TypeT>(mValue.data);
}

template <typename... Ts>
inline bool ConfigItem<Ts...>::Exists() const noexcept
{
    return !std::holds_alternative<std::monostate>(mValue.data);
}

template <typename... Ts>
inline bool ConfigItem<Ts...>::IsNull() const noexcept
{
    return std::holds_alternative<std::monostate>(mValue.data);
}

template <typename... Ts>
inline bool ConfigItem<Ts...>::IsObject() const noexcept
{
    return std::holds_alternative<std::unordered_map<std::string, ConfigValue<Ts...>>>(mValue.data);
}

template <typename... Ts>
inline bool ConfigItem<Ts...>::IsArray() const noexcept
{
    return std::holds_alternative<std::vector<ConfigValue<Ts...>>>(mValue.data);
}

template <typename... Ts>
inline auto &clv::config::ConfigItem<Ts...>::GetDictItem(const std::string &key) noexcept
{
    auto *dict_ptr = std::get_if<std::unordered_map<std::string, ConfigValue<Ts...>>>(&mValue.data);
    if (!dict_ptr)
        return null_value<Ts...>;

    auto it = dict_ptr->find(key);
    if (it == dict_ptr->end())
        return null_value<Ts...>;

    return it->second;
}

template <typename... Ts>
inline auto &ConfigItem<Ts...>::GetArrayItem(size_t index) noexcept
{
    auto *arr_ptr = std::get_if<std::vector<ConfigValue<Ts...>>>(&mValue.data);
    if (!arr_ptr || index >= arr_ptr->size())
        return null_value<Ts...>;

    return (*arr_ptr)[index];
}

template <typename... Ts>
template <typename TypeT>
inline bool ConfigItem<Ts...>::IsType() const noexcept
{
    return std::holds_alternative<TypeT>(mValue.data);
}

template <typename... Ts>
template <typename TypeT>
inline bool ConfigItem<Ts...>::Converts() const noexcept
{
    // Direct type match
    if (std::holds_alternative<TypeT>(mValue.data))
        return true;

    // String conversions - any type can attempt conversion from string
    if (std::holds_alternative<std::string>(mValue.data))
        return true;

    return false;
}

// ============================================================================
// Config Inline Implementations
// ============================================================================

// The Meyers idiom isn't really handy here since we need to return a handle
template <typename... Ts>
inline ConfigItem<Ts...> Config<Ts...>::operator[](const std::string &key) noexcept
{
    auto it = mRoot.find(key);
    if (it == mRoot.end())
        return ConfigItem<Ts...>(null_value<Ts...>);
    return ConfigItem<Ts...>(it->second);
}

// The Meyers idiom isn't really handy here since we need to return a handle
template <typename... Ts>
inline const ConfigItem<Ts...> Config<Ts...>::operator[](const std::string &key) const noexcept
{
    auto it = mRoot.find(key);
    if (it == mRoot.end())
        return ConfigItem<Ts...>(null_value<Ts...>);
    return ConfigItem<Ts...>(it->second);
}

template <typename... Ts>
inline void Config<Ts...>::Set(const std::string &key, const ConfigValue<Ts...> &value) noexcept
{
    mRoot[key] = value;
}

template <typename... Ts>
template <typename T>
    requires IsOneOf<T, Ts...>
inline void Config<Ts...>::Set(const std::string &key, const T &value) noexcept
{
    ConfigValue<Ts...> cv;
    cv.data = value;
    mRoot[key] = cv;
}

template <typename... Ts>
inline bool Config<Ts...>::HasKey(const std::string &key) const noexcept
{
    return mRoot.count(key) > 0;
}

template <typename... Ts>
inline size_t Config<Ts...>::Size() const noexcept
{
    return mRoot.size();
}

template <typename... Ts>
template <typename FunctionT>
inline void Config<Ts...>::ForEach(FunctionT &&fn) const noexcept
{
    for (const auto &[key, val] : mRoot)
    {
        fn(std::string_view(key), ConfigItem<Ts...>(val));
    }
}

template <typename... Ts>
inline void Config<Ts...>::Clear() noexcept
{
    mRoot.clear();
}

template <typename... Ts>
inline auto Config<Ts...>::GetRoot() noexcept -> dict_t &
{
    return mRoot;
}

} // namespace clv::config

#endif // CLV_CONFIG_H
