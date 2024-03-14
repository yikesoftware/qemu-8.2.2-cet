t = []
if get_option('plugins')
  foreach i : ['bb', 'empty', 'insn', 'mem', 'syscall', 'cet']
    if targetos == 'windows'
      t += shared_module(i, files(i + '.c') + '../../contrib/plugins/win32_linker.c',
                        include_directories: '../../include/qemu',
                        link_depends: [win32_qemu_plugin_api_lib],
                        link_args: ['-Lplugins', '-lqemu_plugin_api'],
                        dependencies: glib)

    else
      inc_dirs = include_directories('../../include/qemu')
      t += shared_module(i, files(i + '.c'),
                        include_directories: inc_dirs,
                        dependencies: glib)
    endif
  endforeach
endif
if t.length() > 0
  alias_target('test-plugins', t)
else
  run_target('test-plugins', command: find_program('true'))
endif
