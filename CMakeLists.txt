cmake_minimum_required(VERSION 3.25)

project(mrryyourfolder)

add_executable(mrryyourfolder)
target_sources(mrryyourfolder
  PRIVATE
    src/main.c
)
set_property(TARGET mrryyourfolder PROPERTY C_STANDARD 23)
set_property(TARGET mrryyourfolder PROPERTY C_STANDARD_REQUIRED ON)
set_property(TARGET mrryyourfolder PROPERTY C_EXTENSIONS OFF)
