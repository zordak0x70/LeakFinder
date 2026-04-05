project(
    'LeakFinder',
    'c',
    version : '0.1.0',
    default_options : [
      'c_std=c23',
      'warning_level=3',
      'buildtype=release', 
      'b_lto=true'
    ]
)

cc = meson.get_compiler('c')
c_args = []
link_args = []

if get_option('buildtype') == 'debug'
    if cc.has_argument('-ggdb')
        c_args += '-ggdb'
    endif
    message('[MESON] Debug build choice')

elif get_option('buildtype') == 'release'
    if cc.has_argument('-march=native')
        c_args += '-march=native'
    endif

    aggressive_flags = [
        '-fomit-frame-pointer',
        '-fno-semantic-interposition'
    ]

    foreach arg : aggressive_flags
        if cc.has_argument(arg)
            c_args += arg
        endif
    endforeach

    message('[MESON] Release build choice')
endif

src = files(
    'src/main.c',
)

incdir = include_directories('include')

libgit2_dep = dependency('libgit2',
  required : true,
  version : '>=1.7.0'
)

executable(
    'leakfinder',
    src,
    c_args : c_args,
    link_args : link_args,
    include_directories : incdir,
    dependencies : [libgit2_dep],
    install : true
)
