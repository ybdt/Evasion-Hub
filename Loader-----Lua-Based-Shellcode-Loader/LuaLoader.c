#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

typedef struct {
    const char* p;
    size_t size;
} MemReaderData;

const char* my_lua_reader(lua_State* L, void* ud, size_t* sz) {
    MemReaderData* data = (MemReaderData*)ud;
    if (data->size == 0) {
        return NULL;
    }
    *sz = data->size;
    data->size = 0;
    return data->p;
}

int main(int argc, char* argv[]) {
    lua_State* L = luaL_newstate();

    luaL_openlibs(L);

    const char* filename = "externel-script.lua";
    FILE* f = fopen(filename, "rb");

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* script_buffer = (char*)malloc(filesize);

    size_t read_len = fread(script_buffer, 1, filesize, f);
    fclose(f);

    MemReaderData reader_data;
    reader_data.p = script_buffer;
    reader_data.size = filesize;

    int status = lua_load(L, my_lua_reader, &reader_data, "script");

    free(script_buffer);

    status = lua_pcall(L, 0, LUA_MULTRET, 0);

    lua_close(L);
    return 0;
}