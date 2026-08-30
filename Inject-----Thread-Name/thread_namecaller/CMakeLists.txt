cmake_minimum_required (VERSION 3.10)

project ( thread_namecaller )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	../common.cpp
	../ntdll_wrappers.cpp
)

set (hdrs
	../common.h
	../ntddk.h
	../ntdll_wrappers.h
	shellcode.h
	rop_api.h
)

if(USE_OLD_APC_API)
	set (srcs
		${srcs}
		../check_alertable.cpp
	)
	set (hdrs
		${hdrs}
		../check_alertable.h
	)
endif()


if(USE_ROP)
	set (hdrs
		${hdrs}
		rop_api.h
	)
endif()


add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
