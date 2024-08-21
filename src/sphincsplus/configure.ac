AC_PREREQ([2.60])

# The package (a.k.a. release) version based on semantic versioning 2.0.0 of the API.
define(_PKG_VERSION_MAJOR, 1)
define(_PKG_VERSION_MINOR, 0)
define(_PKG_VERSION_PATCH, 0)
define(_PKG_VERSION_IS_RELEASE, false)

# The library version is based on libtool versioning of the ABI.
# Update these numbers following the rules here:
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
define(_LIB_VERSION_CURRENT, 1)
define(_LIB_VERSION_REVISION, 0)
define(_LIB_VERSION_AGE, 0)

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])

# Initialize the package with its name, version, and additional metadata.
AC_INIT([libsphincsplus],
    m4_join([.], _PKG_VERSION_MAJOR, _PKG_VERSION_MINOR, _PKG_VERSION_PATCH)m4_if(_PKG_VERSION_IS_RELEASE, [true], [], [-dev]),
    [https://github.com/Quranium/Quranium_Core/issues],
    [libsphincsplus],
    [https://github.com/Quranium/Quranium_Core])

# Optional: Set the path to a README file to display package information.
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_PROG_CXX
AC_PROG_CC
LT_INIT

# Clear some cache variables as a workaround for a bug that appears due to a bad
# interaction between AM_PROG_AR and LT_INIT when combining MSVC's archiver lib.exe.
# https://debbugs.gnu.org/cgi/bugreport.cgi?bug=54421
AS_UNSET(ac_cv_prog_AR)
AS_UNSET(ac_cv_prog_ac_ct_AR)
LT_INIT([win32-dll])

build_windows=no

case $host_os in
  *darwin*)
     if  test x$cross_compiling != xyes; then
       AC_CHECK_PROG([BREW], brew, brew)
       if test x$BREW = xbrew; then
         # These Homebrew packages may be keg-only, meaning that they won't be found
         # in expected paths because they may conflict with system files. Ask
         # Homebrew where each one is located, then adjust paths accordingly.
         if $BREW list --versions valgrind >/dev/null; then
           valgrind_prefix=$($BREW --prefix valgrind 2>/dev/null)
           VALGRIND_CPPFLAGS="-I$valgrind_prefix/include"
         fi
       else
         AC_CHECK_PROG([PORT], port, port)
         # If homebrew isn't installed and macports is, add the macports default paths
         # as a last resort.
         if test x$PORT = xport; then
           CPPFLAGS="$CPPFLAGS -isystem /opt/local/include"
           LDFLAGS="$LDFLAGS -L/opt/local/lib"
         fi
       fi
     fi
   ;;
   cygwin*|mingw*)
     build_windows=yes
   ;;
esac

# Use autoconf-archive macros to check and define compiler flags for specific CPU features.
# Enable AVX2 instructions.
AX_COMPILER_FLAGS_CFLAGS([avx2], [-mavx2])

# Enable AVX512F instructions.
AX_COMPILER_FLAGS_CFLAGS([avx512f], [-mavx512f])

# Substitute the CFLAGS variable with additional flags for the compiler.
# Includes AVX2, AVX512F, and Skylake AVX512 architecture optimizations.
AC_SUBST([CFLAGS], "$CFLAGS -mavx2 -mavx512f -march=skylake-avx512")

# Specify the directory containing additional autoconf macros.
AC_CONFIG_MACRO_DIRS([build-aux/m4])

# Generate Makefile from Makefile.am.
AC_CONFIG_FILES([Makefile libsphincsplus.pc])

# Create the output configuration files specified by AC_CONFIG_FILES.
AC_OUTPUT
