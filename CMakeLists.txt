cmake_minimum_required(VERSION 3.10)
project(GumTrace CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Frida 版本选择: 16 或 17 (默认 17)
option(FRIDA_VERSION "Frida Gum major version (16 or 17)" 17)
message(STATUS "Frida version: ${FRIDA_VERSION}")

include_directories(${CMAKE_SOURCE_DIR}/libs)
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/src)

set(GUMTRACE_SOURCES
        src/main.cpp
        src/GumTrace.cpp
        src/Utils.cpp
        src/CallbackContext.cpp
        src/FuncPrinter.cpp
)

add_library(GumTrace SHARED
        ${GUMTRACE_SOURCES}
)

# 传递 Frida 版本宏到源码
target_compile_definitions(GumTrace PRIVATE FRIDA_VERSION=${FRIDA_VERSION})

if(ANDROID)
    message(STATUS "Configuring for Android")

    set(ANDROID_SYSROOT_INCLUDE "${CMAKE_SYSROOT}/usr/include")

    target_include_directories(GumTrace SYSTEM PUBLIC .
            ${ANDROID_SYSROOT_INCLUDE})

    if(FRIDA_VERSION GREATER_EQUAL 17)
        target_link_libraries(GumTrace PRIVATE ${CMAKE_SOURCE_DIR}/libs/FridaGum-Android-17.8.3-fix.a)
    else()
        target_link_libraries(GumTrace PRIVATE ${CMAKE_SOURCE_DIR}/libs/FridaGum-Android-16-fix.a)
    endif()
    target_link_libraries(GumTrace PRIVATE log dl m z)

else()
    message(STATUS "Configuring for iOS")

    enable_language(OBJCXX)

    execute_process(
            COMMAND xcode-select -p
            OUTPUT_VARIABLE DEVELOPER_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT DEVELOPER_DIR)
        message(FATAL_ERROR "Unable to locate Xcode developer directory")
    endif()

    set(CMAKE_XCODE_DEVELOPER_DIR ${DEVELOPER_DIR})

    execute_process(
            COMMAND /usr/bin/env DEVELOPER_DIR=${DEVELOPER_DIR} xcrun --sdk iphoneos --show-sdk-path
            OUTPUT_VARIABLE IOS_SDK_PATH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    set(CMAKE_OSX_SYSROOT ${IOS_SDK_PATH})
    message(STATUS "iOS SDK Path: ${IOS_SDK_PATH}")

    set_source_files_properties(${GUMTRACE_SOURCES} PROPERTIES LANGUAGE OBJCXX)

    target_include_directories(GumTrace SYSTEM PUBLIC .)

    set_target_properties(GumTrace PROPERTIES
            LINKER_LANGUAGE OBJCXX
            OBJCXX_STANDARD 11
            OBJCXX_STANDARD_REQUIRED YES
            BUNDLE FALSE
            FRAMEWORK FALSE
            XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO"
            XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO"
            XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER ""
            MACOSX_BUNDLE FALSE
    )

    target_compile_options(GumTrace PRIVATE
            -isysroot ${IOS_SDK_PATH}
            -arch arm64
            -miphoneos-version-min=12.0
            -fvisibility=hidden
            -Wno-unused-command-line-argument
    )

    target_link_options(GumTrace PRIVATE
            -isysroot ${IOS_SDK_PATH}
            -arch arm64
            -miphoneos-version-min=12.0
    )

    if(FRIDA_VERSION GREATER_EQUAL 17)
        target_link_libraries(GumTrace
                ${CMAKE_SOURCE_DIR}/libs/FridaGum-IOS-17.8.3-fix.a
                "-framework Foundation"
                "-framework CoreFoundation"
        )
    else()
        target_link_libraries(GumTrace
                ${CMAKE_SOURCE_DIR}/libs/FridaGum-IOS-16-fix.a
                "-framework Foundation"
                "-framework CoreFoundation"
        )
    endif()
endif()
