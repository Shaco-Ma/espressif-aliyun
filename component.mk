#
# Component Makefile
#
COMPONENT_ADD_INCLUDEDIRS := \
    iotkit-embedded-2.3.0/src/sdk-impl \
    iotkit-embedded-2.3.0/src/infra/log \
    iotkit-embedded-2.3.0/src/infra/system \
    iotkit-embedded-2.3.0/src/infra/utils \
    iotkit-embedded-2.3.0/include \
    iotkit-embedded-2.3.0/include/exports \
    iotkit-embedded-2.3.0/include/imports

COMPONENT_SRCDIRS := \
    platform/os/espressif \
    platform/ssl/mbedtls 

# link libiot_sdk.a
LIBS += iot_sdk
COMPONENT_ADD_LDFLAGS += -L $(COMPONENT_PATH)/iotkit-embedded-2.3.0/output/release/lib $(addprefix -l,$(LIBS))
