// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "pid_controller.h"

#include <gtest/gtest.h>

#include <cmath>

using clv::PidController;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static constexpr double kEps = 1e-9;

// Run the controller for N steps at fixed dt and return the last output.
static double RunSteps(PidController<> &pid, double setpoint, double measurement,
                       double dt, int steps)
{
    double out = 0.0;
    for (int i = 0; i < steps; ++i)
        out = pid.Update(setpoint, measurement, dt);
    return out;
}

// ---------------------------------------------------------------------------
// P-only controller
// ---------------------------------------------------------------------------

TEST(PidControllerTest, POnly_ZeroErrorProducesZeroOutput)
{
    PidController<> pid;
    pid.kp = 2.0;
    pid.Reset(0.5);
    EXPECT_NEAR(pid.Update(0.5, 0.5, 1.0), 0.0, kEps);
}

TEST(PidControllerTest, POnly_PositiveErrorProducesPositiveOutput)
{
    PidController<> pid;
    pid.kp = 3.0;
    pid.Reset(0.0);
    // error = 1.0 - 0.0 = 1.0, output = kp * error = 3.0
    EXPECT_NEAR(pid.Update(1.0, 0.0, 1.0), 3.0, kEps);
}

TEST(PidControllerTest, POnly_NegativeErrorProducesNegativeOutput)
{
    PidController<> pid;
    pid.kp = 2.0;
    pid.Reset(1.0);
    // error = 0.0 - 1.0 = -1.0, output = -2.0
    EXPECT_NEAR(pid.Update(0.0, 1.0, 1.0), -2.0, kEps);
}

// ---------------------------------------------------------------------------
// PI controller — integral accumulation
// ---------------------------------------------------------------------------

TEST(PidControllerTest, PI_IntegralAccumulatesOverTime)
{
    PidController<> pid;
    pid.kp = 0.0;
    pid.ki = 1.0;
    pid.Reset(0.0);

    // Each tick: integral += ki * error * dt = 1.0 * 1.0 * 0.5 = 0.5
    // After 4 ticks: integral = 2.0, output = 2.0
    for (int i = 0; i < 4; ++i)
        pid.Update(1.0, 0.0, 0.5);

    EXPECT_NEAR(pid.Integral(), 2.0, kEps);
    EXPECT_NEAR(pid.Update(1.0, 0.0, 0.5), 2.5, kEps); // 5th tick
}

TEST(PidControllerTest, PI_IntegralDecaysWhenErrorChangesSign)
{
    PidController<> pid;
    pid.kp = 0.0;
    pid.ki = 1.0;
    pid.Reset(0.0);

    // Accumulate 10 ticks with positive error
    for (int i = 0; i < 10; ++i)
        pid.Update(1.0, 0.0, 1.0);
    EXPECT_NEAR(pid.Integral(), 10.0, kEps);

    // Now negative error — integral should decrease
    pid.Update(0.0, 1.0, 1.0); // error = -1.0, integral += -1.0
    EXPECT_NEAR(pid.Integral(), 9.0, kEps);
}

TEST(PidControllerTest, PI_AntiWindupClampsIntegral)
{
    PidController<> pid;
    pid.kp = 0.0;
    pid.ki = 1.0;
    pid.integralMin = -5.0;
    pid.integralMax = 5.0;
    pid.Reset(0.0);

    // Drive integral way past the clamp
    for (int i = 0; i < 20; ++i)
        pid.Update(100.0, 0.0, 1.0);

    EXPECT_NEAR(pid.Integral(), 5.0, kEps);
}

// ---------------------------------------------------------------------------
// Output clamping
// ---------------------------------------------------------------------------

TEST(PidControllerTest, OutputIsClampedToMax)
{
    PidController<> pid;
    pid.kp = 100.0;
    pid.outputMax = 10.0;
    pid.outputMin = -10.0;
    pid.Reset(0.0);

    double out = pid.Update(1.0, 0.0, 1.0); // unclamped = 100.0
    EXPECT_NEAR(out, 10.0, kEps);
}

TEST(PidControllerTest, OutputIsClampedToMin)
{
    PidController<> pid;
    pid.kp = 100.0;
    pid.outputMax = 10.0;
    pid.outputMin = -10.0;
    pid.Reset(1.0);

    double out = pid.Update(0.0, 1.0, 1.0); // unclamped = -100.0
    EXPECT_NEAR(out, -10.0, kEps);
}

// ---------------------------------------------------------------------------
// Derivative on measurement (no kick on setpoint change)
// ---------------------------------------------------------------------------

TEST(PidControllerTest, PD_DerivativeOnMeasurement_NoKickOnSetpointChange)
{
    // If we change the setpoint but the measurement doesn't move, the D term
    // should be zero because it acts on measurement, not error.
    PidController<> pid;
    pid.kp = 0.0;
    pid.kd = 10.0;
    pid.Reset(0.5); // measurement = 0.5

    // Setpoint jumps from 0.0 to 1.0 — measurement stays at 0.5
    double out = pid.Update(1.0, 0.5, 1.0);
    // d = -kd * (measurement - prevMeasurement) / dt = -10 * (0.5 - 0.5) / 1.0 = 0
    EXPECT_NEAR(out, 0.0, kEps);
}

TEST(PidControllerTest, PD_DerivativeRespondsToMeasurementChange)
{
    PidController<> pid;
    pid.kp = 0.0;
    pid.kd = 2.0;
    pid.Reset(0.0);

    // Measurement rises from 0 to 1 in dt=0.5
    // d = -kd * (1.0 - 0.0) / 0.5 = -2 * 2.0 = -4.0
    double out = pid.Update(0.0, 1.0, 0.5);
    EXPECT_NEAR(out, -4.0, kEps);
}

// ---------------------------------------------------------------------------
// Reset behaviour
// ---------------------------------------------------------------------------

TEST(PidControllerTest, ResetClearsIntegral)
{
    PidController<> pid;
    pid.ki = 1.0;
    pid.Reset(0.0);

    for (int i = 0; i < 5; ++i)
        pid.Update(1.0, 0.0, 1.0);

    EXPECT_GT(pid.Integral(), 0.0);

    pid.Reset(0.0);
    EXPECT_NEAR(pid.Integral(), 0.0, kEps);
}

TEST(PidControllerTest, ResetSetsPrevMeasurement)
{
    PidController<> pid;
    pid.kd = 1.0;
    pid.Reset(0.75);
    EXPECT_NEAR(pid.PrevMeasurement(), 0.75, kEps);
}

TEST(PidControllerTest, AutoInitOnFirstUpdate)
{
    // If Reset() is never called, the first Update() initialises from the
    // incoming measurement so the D term doesn't fire a spike.
    PidController<> pid;
    pid.kd = 100.0;
    pid.kp = 0.0;

    // measurement=0.5 on first call — prevMeasurement should be set to 0.5 → D=0
    double out = pid.Update(1.0, 0.5, 1.0);
    EXPECT_NEAR(out, 0.0, kEps);
    EXPECT_TRUE(pid.IsInitialized());
}

// ---------------------------------------------------------------------------
// dt edge cases
// ---------------------------------------------------------------------------

TEST(PidControllerTest, ZeroDtReturnsZero)
{
    PidController<> pid;
    pid.kp = 5.0;
    pid.Reset(0.0);
    EXPECT_NEAR(pid.Update(1.0, 0.0, 0.0), 0.0, kEps);
}

// ---------------------------------------------------------------------------
// Float instantiation
// ---------------------------------------------------------------------------

TEST(PidControllerTest, FloatInstantiation)
{
    PidController<float> pid;
    pid.kp = 1.0f;
    pid.Reset(0.0f);

    float out = pid.Update(1.0f, 0.0f, 1.0f);
    EXPECT_NEAR(out, 1.0f, 1e-6f);
}

// ---------------------------------------------------------------------------
// Practical scenario: batch fill ratio control (PI)
// ---------------------------------------------------------------------------

TEST(PidControllerTest, BatchFillScenario_ConvergesFromLowFill)
{
    // Simulate: target fill = 0.75, starting fill = 0.30
    // PI controller should accumulate and push batch size up.
    // We don't simulate a real plant here — just verify the output
    // increases monotonically for sustained positive error.
    PidController<> pid;
    pid.kp = 4.0;
    pid.ki = 0.5;
    pid.outputMin = -8.0;
    pid.outputMax = 8.0;
    pid.integralMin = -8.0;
    pid.integralMax = 8.0;
    pid.Reset(0.30);

    double prev = pid.Update(0.75, 0.30, 60.0);
    for (int i = 0; i < 5; ++i)
    {
        double out = pid.Update(0.75, 0.30, 60.0);
        EXPECT_GE(out, prev) << "Output should not decrease when error is constant positive";
        prev = out;
    }
    EXPECT_GT(prev, 0.0);
}

TEST(PidControllerTest, BatchFillScenario_ZeroOutputAtSetpoint)
{
    PidController<> pid;
    pid.kp = 4.0;
    pid.ki = 0.5;
    pid.outputMin = -8.0;
    pid.outputMax = 8.0;
    pid.Reset(0.75);

    // Already at setpoint — P term is zero, integral starts at zero
    double out = pid.Update(0.75, 0.75, 60.0);
    EXPECT_NEAR(out, 0.0, kEps);
}

// ---------------------------------------------------------------------------
// Full PID — all three terms active simultaneously
// ---------------------------------------------------------------------------

TEST(PidControllerTest, PID_AllTermsCombined)
{
    // Verify that the output is the exact arithmetic sum of P + I + D.
    //
    // Setup: kp=2, ki=0.5, kd=1.0, prevMeasurement=0.5
    //
    // Tick 1: setpoint=1.0, measurement=0.8, dt=1.0
    //   error          = 1.0 - 0.8 = 0.2
    //   P              = 2.0 * 0.2          =  0.4
    //   integral       += 0.5 * 0.2 * 1.0  =  0.1  → I = 0.1
    //   dMeasurement   = (0.8 - 0.5) / 1.0 =  0.3
    //   D              = -1.0 * 0.3         = -0.3
    //   output         = 0.4 + 0.1 - 0.3   =  0.2
    //
    // Tick 2: setpoint=1.0, measurement=0.9, dt=2.0
    //   error          = 1.0 - 0.9 = 0.1
    //   P              = 2.0 * 0.1          =  0.2
    //   integral       += 0.5 * 0.1 * 2.0  =  0.1  → integral=0.2, I=0.2
    //   dMeasurement   = (0.9 - 0.8) / 2.0 =  0.05
    //   D              = -1.0 * 0.05        = -0.05
    //   output         = 0.2 + 0.2 - 0.05  =  0.35

    PidController<> pid;
    pid.kp = 2.0;
    pid.ki = 0.5;
    pid.kd = 1.0;
    pid.Reset(0.5);

    EXPECT_NEAR(pid.Update(1.0, 0.8, 1.0), 0.2, kEps);
    EXPECT_NEAR(pid.Integral(), 0.1, kEps);

    EXPECT_NEAR(pid.Update(1.0, 0.9, 2.0), 0.35, kEps);
    EXPECT_NEAR(pid.Integral(), 0.2, kEps);
}
