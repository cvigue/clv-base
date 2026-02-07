// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_PID_CONTROLLER_H
#define CLV_PID_CONTROLLER_H

#include <algorithm>
#include <concepts>
#include <limits>
#include <string>
#include <sstream>
#include <iomanip>

namespace clv {

/// @brief Pass-through filter (no smoothing).
template <std::floating_point T = double>
class PassThroughFilter
{
  public:
    void Reset(T /* unused */)
    {
    }
    T Update(T value)
    {
        return value;
    }
    void SetAlpha(T /* unused */)
    {
    } ///< No-op for pass-through; provided for API consistency
    void SetLastValue(T /* unused */)
    {
    } ///< No-op for pass-through; provided for API consistency
    std::string to_string() const
    {
        return "PassThroughFilter";
    }
};

/// @brief Exponential moving average filter for measurement smoothing.
/// Computes: filtered = alpha * measurement + (1 - alpha) * last_filtered
/// @tparam T Value type (floating point)
template <std::floating_point T = double>
class ExponentialAverageFilter
{
  private:
    T alpha_ = T(1.0); ///< Smoothing factor (0–1); alpha=1 is pass-through, lower = more smoothing
    T last_ = T(0);

  public:
    explicit ExponentialAverageFilter(T alpha = T(1.0)) : alpha_(alpha)
    {
    }

    void Reset(T initialValue)
    {
        last_ = initialValue;
    }

    T Update(T value)
    {
        last_ = alpha_ * value + (T(1) - alpha_) * last_;
        return last_;
    }

    T GetAlpha() const
    {
        return alpha_;
    }
    void SetAlpha(T alpha)
    {
        alpha_ = alpha;
    }
    void SetLastValue(T value)
    {
        last_ = value; ///< Prime the filter state directly (used during warmup periods)
    }

    std::string to_string() const
    {
        std::ostringstream ss;
        ss << "ExponentialAverageFilter(alpha=" << std::fixed << std::setprecision(3) << alpha_ << ")";
        return ss.str();
    }
};

/// @brief Rate-limited gate filter: allows at most ±maxDelta per cycle.
/// Useful for smoothing noisy measurements with sharp transitions.
template <std::floating_point T = double>
class GateFilter
{
  private:
    T maxDelta_ = std::numeric_limits<T>::max();
    T last_ = T(0);

  public:
    explicit GateFilter(T maxDelta = std::numeric_limits<T>::max()) : maxDelta_(maxDelta)
    {
    }

    void Reset(T initialValue)
    {
        last_ = initialValue;
    }

    T Update(T value)
    {
        T delta = value - last_;
        delta = std::clamp(delta, -maxDelta_, maxDelta_);
        last_ = last_ + delta;
        return last_;
    }

    T GetMaxDelta() const
    {
        return maxDelta_;
    }
    void SetMaxDelta(T maxDelta)
    {
        maxDelta_ = maxDelta;
    }
    void SetAlpha(T /* unused */)
    {
    } ///< No-op for gate filter; provided for API consistency
    void SetLastValue(T value)
    {
        last_ = value; ///< Prime the filter state directly (used during warmup periods)
    }

    std::string to_string() const
    {
        std::ostringstream ss;
        ss << "GateFilter(maxDelta=" << std::fixed << std::setprecision(3) << maxDelta_ << ")";
        return ss.str();
    }
};

/// @brief Discrete-time PID controller with optional measurement filtering.
///
/// Computes a control output given a measured process variable and a target
/// setpoint. The derivative term acts on the *measurement* (not the error) to
/// avoid derivative kick on step changes to the setpoint.
///
/// All gains and limits use the same value type T (default double).
///
/// @tparam T Value type (floating point)
/// @tparam MeasurementFilter Filter class to apply to measurements before PID logic
///
/// Usage:
/// @code
///     // Without filtering:
///     PidController<double> pid;
///     pid.kp = 1.0; pid.ki = 0.1;
///     pid.Reset(currentMeasurement);
///     double delta = pid.Update(targetFill, measuredFill, dt);
///
///     // With exponential smoothing:
///     PidController<double, ExponentialAverageFilter<double>> pid(
///         ExponentialAverageFilter<double>(0.3));  // 30% smoothing
///     pid.kp = 1.0; pid.ki = 0.1;
///     pid.Reset(currentMeasurement);
///     double delta = pid.Update(targetFill, measuredFill, dt);
/// @endcode
///
/// Setting kd=0 gives a PI controller. Setting ki=0 gives a P controller.
template <std::floating_point T = double, typename MeasurementFilter = PassThroughFilter<T>>
class PidController
{
  public:
    // -----------------------------------------------------------------
    // Configuration (public, set before first use or after Reset)
    // -----------------------------------------------------------------

    T kp = T(1);                                        ///< Proportional gain
    T ki = T(0);                                        ///< Integral gain (0 = no integral)
    T kd = T(0);                                        ///< Derivative gain (0 = no derivative)
    T outputMin = std::numeric_limits<T>::lowest();     ///< Output clamp lower bound
    T outputMax = std::numeric_limits<T>::max();        ///< Output clamp upper bound
    T integralMin = std::numeric_limits<T>::lowest();   ///< Anti-windup: integral clamp lower (default: same as output)
    T integralMax = std::numeric_limits<T>::max();      ///< Anti-windup: integral clamp upper (default: same as output)
    T integralDecay = T(1);                             ///< Leak factor applied to accumulator each cycle (1 = no decay, <1 = leak toward zero)
    T integralErrorMax = std::numeric_limits<T>::max(); ///< Error window: per-cycle error seen by integrator is clamped to ±this
    T slewMax = std::numeric_limits<T>::max();          ///< Max change in output per cycle (∞ = no slew limit)

    /// @brief Construct with optional measurement filter instance.
    explicit PidController(MeasurementFilter filter = MeasurementFilter())
        : measurementFilter_(std::move(filter))
    {
    }

    /// @brief Get mutable reference to the measurement filter.
    MeasurementFilter &GetFilter()
    {
        return measurementFilter_;
    }
    const MeasurementFilter &GetFilter() const
    {
        return measurementFilter_;
    }

    // -----------------------------------------------------------------
    // Control
    // -----------------------------------------------------------------

    /// @brief Reset controller state.
    ///
    /// Should be called before the first Update() and whenever the process
    /// is restarted. Initialises the previous measurement for the derivative
    /// term so the first tick doesn't produce a spike.
    ///
    /// @param initialMeasurement Current process variable value before control begins.
    void Reset(T initialMeasurement = T(0))
    {
        integral_ = T(0);
        prevMeasurement_ = initialMeasurement;
        lastOutput_ = T(0);
        measurementFilter_.Reset(initialMeasurement);
        initialized_ = true;
    }

    /// @brief Compute and return the control output for this timestep.
    ///
    /// @param setpoint  The desired target value for the process variable.
    /// @param measurement  The measured process variable this tick.
    /// @param dt  Time elapsed since the last Update() call (seconds). Must be > 0.
    /// @return Control output, clamped to [outputMin, outputMax].
    T Update(T setpoint, T measurement, T dt)
    {
        if (!initialized_)
            Reset(measurement);

        if (dt <= T(0))
            return T(0);

        // Apply measurement filter
        const T filtered = measurementFilter_.Update(measurement);

        const T error = setpoint - filtered;

        // Proportional
        lastP_ = kp * error;

        // Integral with decay, error-window clamping, and anti-windup
        integral_ *= integralDecay;
        integral_ += ki * std::clamp(error, -integralErrorMax, integralErrorMax) * dt;
        integral_ = std::clamp(integral_, integralMin, integralMax);
        lastI_ = integral_;

        // Derivative on measurement (avoids kick on setpoint changes)
        const T dMeasurement = (filtered - prevMeasurement_) / dt;
        lastD_ = -kd * dMeasurement;

        prevMeasurement_ = filtered;

        const T raw = std::clamp(lastP_ + lastI_ + lastD_, outputMin, outputMax);
        const T slewed = std::clamp(raw, lastOutput_ - slewMax, lastOutput_ + slewMax);
        lastOutput_ = slewed;
        return slewed;
    }

    // -----------------------------------------------------------------
    // Inspection
    // -----------------------------------------------------------------

    /// @brief Proportional term from the last Update() call.
    T LastP() const
    {
        return lastP_;
    }
    /// @brief Integral term (accumulator) from the last Update() call.
    T LastI() const
    {
        return lastI_;
    }
    /// @brief Derivative term from the last Update() call.
    T LastD() const
    {
        return lastD_;
    }

    /// @brief Current integral accumulator value.
    T Integral() const
    {
        return integral_;
    }

    /// @brief Previous measurement (used for derivative term).
    T PrevMeasurement() const
    {
        return prevMeasurement_;
    }

    /// @brief Output value from the last Update() call (after slew limiting).
    T LastOutput() const
    {
        return lastOutput_;
    }

    /// @brief Whether Reset() has been called at least once.
    bool IsInitialized() const
    {
        return initialized_;
    }

  private:
    T integral_ = T(0);
    T prevMeasurement_ = T(0);
    T lastOutput_ = T(0);
    T lastP_ = T(0);
    T lastI_ = T(0);
    T lastD_ = T(0);
    bool initialized_ = false;
    MeasurementFilter measurementFilter_;
};

} // namespace clv

#endif // CLV_PID_CONTROLLER_H
