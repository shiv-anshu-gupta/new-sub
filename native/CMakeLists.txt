cmake_minimum_required(VERSION 3.16)
project(sv_subscriber VERSION 2.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================================
# Options
# ============================================================================

option(ENABLE_PHASOR "Build with phasor estimation module" OFF)
option(ENABLE_MKL    "Use Intel MKL for FFT (requires MKL)" OFF)

# ============================================================================
# Source files
# ============================================================================

set(LIB_SOURCES
    src/asn1_ber_decoder.cc
    src/sv_decoder.cc
    src/sv_capture.cc
)

if(ENABLE_PHASOR)
    list(APPEND LIB_SOURCES src/sv_phasor.cc)
endif()

set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ============================================================================
# Find libpcap
# ============================================================================

find_library(PCAP_LIB pcap)
if(NOT PCAP_LIB)
    message(FATAL_ERROR "libpcap not found. Install with: sudo apt install libpcap-dev")
endif()

# ============================================================================
# Static library (decoder + capture)
# ============================================================================

add_library(sv_lib STATIC ${LIB_SOURCES})
target_include_directories(sv_lib PUBLIC ${INCLUDE_DIRS})
target_link_libraries(sv_lib PUBLIC ${PCAP_LIB})

if(ENABLE_PHASOR)
    target_compile_definitions(sv_lib PUBLIC ENABLE_PHASOR)
endif()

if(ENABLE_MKL)
    find_package(MKL QUIET)
    if(MKL_FOUND)
        target_link_libraries(sv_lib PUBLIC MKL::MKL)
    else()
        # Fallback: assume MKL is on the system include/lib path
        target_link_libraries(sv_lib PUBLIC mkl_rt)
    endif()
    target_compile_definitions(sv_lib PUBLIC ENABLE_MKL)
endif()

# ============================================================================
# Executable
# ============================================================================

add_executable(sv_subscriber src/main.cc)
target_link_libraries(sv_subscriber PRIVATE sv_lib)

# ============================================================================
# Install
# ============================================================================

install(TARGETS sv_subscriber RUNTIME DESTINATION bin)

install(FILES
    include/asn1_ber_decoder.h
    include/sv_decoder.h
    include/sv_capture.h
    DESTINATION include
)

if(ENABLE_PHASOR)
    install(FILES include/sv_phasor.h DESTINATION include)
endif()

message(STATUS "sv_subscriber ${PROJECT_VERSION}")
message(STATUS "  Phasor: ${ENABLE_PHASOR}")
message(STATUS "  MKL:    ${ENABLE_MKL}")
