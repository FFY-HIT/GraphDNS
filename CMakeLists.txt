cmake_minimum_required(VERSION 3.16)

project(GraphDNS LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenMP REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)

add_executable(preprocess src/preprocess.cpp)
target_link_libraries(preprocess PRIVATE OpenMP::OpenMP_CXX nlohmann_json::nlohmann_json)

add_executable(semantic_graph src/semantic_graph.cpp)
target_link_libraries(semantic_graph PRIVATE OpenMP::OpenMP_CXX)

foreach(target preprocess semantic_graph)
  if(MSVC)
    target_compile_options(${target} PRIVATE /O2 /W4)
  else()
    target_compile_options(${target} PRIVATE -O3 -Wall -Wextra)
  endif()
endforeach()
