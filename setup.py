from cx_Freeze import setup, Executable
from stu2srec_version  import version

# Dependencies are automatically detected, but it might need
# fine tuning.
buildOptions = dict(packages = [], 
                    excludes = [],
					include_msvcr = True, #skip error msvcr100.dll missing
                    include_files = ['example.stu', 'RELEASE.txt'])

base = 'Console'

executables = [
    Executable('stu2srec_main.py', base=base, targetName = 'stu2srec.exe')
]

setup(name='stu2srec',
      version = version,
      description = '',
      options = dict(build_exe = buildOptions),
      executables = executables)
