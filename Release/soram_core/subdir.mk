################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../soram_core/SORAM.cpp 

OBJS += \
./soram_core/SORAM.o 

CPP_DEPS += \
./soram_core/SORAM.d 


# Each subdirectory must supply rules for building sources it contributes
soram_core/%.o: ../soram_core/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


