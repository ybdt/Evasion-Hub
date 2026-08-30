cmake_minimum_required ( VERSION 3.10 )

project ( thread_namecalling_demo )

option( USE_NEW_THREADS "Inject into newly created threads (rather than to existing ones)" OFF )
option( USE_OLD_APC_API "Use the old API for APC injections" OFF )
option( USE_NEW_BUFFER "Copy injected buffer into a newly allocated memory area" OFF )
option( USE_ROP "Use ROP to call VirtualProtect/VirtualAlloc" OFF )

if(USE_NEW_THREADS)
    add_compile_definitions(USE_NEW_THREADS)
endif()

if(USE_OLD_APC_API)
    add_compile_definitions(USE_OLD_APC_API)
endif()

if(USE_NEW_BUFFER)
    add_compile_definitions(USE_NEW_BUFFER)
endif()

if(USE_ROP)
    add_compile_definitions(USE_ROP)
endif()


# Add sub-directories
#
add_subdirectory ( thread_namecaller )
add_subdirectory ( thread_receive )
add_subdirectory ( dll_inj )
