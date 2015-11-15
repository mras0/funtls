file(TO_NATIVE_PATH ${CMD1} CMD1)
file(TO_NATIVE_PATH ${CMD2} CMD2)
string(REPLACE "\"" "" CMD1_ARGS ${CMD1_ARGS})
separate_arguments(CMD1_ARGS)
string(REPLACE "\"" "" CMD2_ARGS ${CMD2_ARGS})
separate_arguments(CMD2_ARGS)

execute_process(COMMAND ${CMD1} ${CMD1_ARGS}
                COMMAND ${CMD2} ${CMD2_ARGS}
                RESULT_VARIABLE rv)

if (rv)
    message(FATAL_ERROR "${CMD1} ${CMD1_ARGS} | ${CMD2} ${CMD2_ARGS}\nFAILED\nRES=${rv}")
endif()
