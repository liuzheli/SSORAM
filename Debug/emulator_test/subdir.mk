################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../emulator_test/estimate.cpp 

OBJS += \
./emulator_test/estimate.o 

CPP_DEPS += \
./emulator_test/estimate.d 


# Each subdirectory must supply rules for building sources it contributes
emulator_test/%.o: ../emulator_test/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0  -std=c++11 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


