cmake_minimum_required (VERSION 3.10)

project ( dll_inj )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	../common.cpp
	../ntdll_wrappers.cpp
)


set (hdrs
	../common.h
	../ntdll_wrappers.h
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

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
