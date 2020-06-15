use libc::c_ushort;
use std::{
    ffi::{CStr, OsStr, OsString},
    fs::{File, OpenOptions},
    io::{Error as IoErr, Read, Write},
    mem,
    os::unix::{io::FromRawFd, prelude::*, process::CommandExt},
    process::{self, Child},
};

pub struct PtyMaster {
    inner: File,
}

impl PtyMaster {
    /// Open a pseudo-TTY master.
    ///
    /// This function performs the C library calls `posix_openpt()`, `grantpt()`, and `unlockpt()`.
    pub fn open() -> Result<Self, IoErr> {
        let inner = unsafe {
            let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);

            if fd < 0 {
                return Err(IoErr::last_os_error());
            }

            if libc::grantpt(fd) != 0 {
                return Err(IoErr::last_os_error());
            }

            if libc::unlockpt(fd) != 0 {
                return Err(IoErr::last_os_error());
            }

            File::from_raw_fd(fd)
        };

        Ok(Self { inner })
    }

    /// Open a pseudo-TTY slave that is connected to this master.
    pub fn open_slave(&self) -> Result<File, IoErr> {
        let mut buf: [libc::c_char; 512] = [0; 512];
        let fd = self.as_raw_fd();

        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        {
            if unsafe { libc::ptsname_r(fd, buf.as_mut_ptr(), buf.len()) } != 0 {
                return Err(IoErr::last_os_error());
            }
        }

        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        unsafe {
            let st = libc::ptsname(fd);
            if st.is_null() {
                return Err(IoErr::last_os_error());
            }
            libc::strncpy(buf.as_mut_ptr(), st, buf.len());
        }

        let ptsname = OsStr::from_bytes(unsafe { CStr::from_ptr(&buf as _) }.to_bytes());

        OpenOptions::new().read(true).write(true).open(ptsname)
    }

    pub fn ptsname(&self) -> Result<OsString, IoErr> {
        let mut buf: [libc::c_char; 512] = [0; 512];
        let fd = self.as_raw_fd();

        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        {
            if unsafe { libc::ptsname_r(fd, buf.as_mut_ptr(), buf.len()) } != 0 {
                return Err(IoErr::last_os_error());
            }
        }
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        unsafe {
            let st = libc::ptsname(fd);
            if st.is_null() {
                return Err(IoErr::last_os_error());
            }
            libc::strncpy(buf.as_mut_ptr(), st, buf.len());
        }
        let ptsname = OsStr::from_bytes(unsafe { CStr::from_ptr(&buf as _) }.to_bytes());
        Ok(ptsname.to_os_string())
    }

    pub fn winsize(&self) -> Result<(c_ushort, c_ushort), IoErr> {
        let fd = self.as_raw_fd();
        let mut winsz: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut winsz) } != 0 {
            return Err(IoErr::last_os_error());
        }
        Ok((winsz.ws_row, winsz.ws_col))
    }

    pub fn resize(&self, rows: c_ushort, cols: c_ushort) -> Result<(), IoErr> {
        let fd = self.as_raw_fd();
        let winsz = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsz) } != 0 {
            return Err(IoErr::last_os_error());
        }
        Ok(())
    }
}

impl Read for PtyMaster {
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, IoErr> {
        self.inner.read(bytes)
    }
}

impl Write for PtyMaster {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, IoErr> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> Result<(), IoErr> {
        self.inner.flush()
    }
}

impl Read for &'_ PtyMaster {
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, IoErr> {
        (&self.inner).read(bytes)
    }
}

impl Write for &'_ PtyMaster {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, IoErr> {
        (&self.inner).write(bytes)
    }

    fn flush(&mut self) -> Result<(), IoErr> {
        (&self.inner).flush()
    }
}

impl AsRawFd for PtyMaster {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

/// A private trait for the extending `std::process::Command`.
trait CommandExtInternal {
    fn spawn_pty_full(&mut self, ptymaster: &PtyMaster, raw: bool) -> Result<Child, IoErr>;
}

impl CommandExtInternal for process::Command {
    fn spawn_pty_full(&mut self, ptymaster: &PtyMaster, raw: bool) -> Result<Child, IoErr> {
        let master_fd = ptymaster.as_raw_fd();
        let slave = ptymaster.open_slave()?;
        let slave_fd = slave.as_raw_fd();

        self.stdin(slave.try_clone()?);
        self.stdout(slave.try_clone()?);
        self.stderr(slave);

        // XXX any need to close slave handles in the parent process beyond
        // what's done here?

        unsafe {
            self.pre_exec(move || {
                if raw {
                    let mut attrs: libc::termios = mem::zeroed();

                    if libc::tcgetattr(slave_fd, &mut attrs as _) != 0 {
                        return Err(IoErr::last_os_error());
                    }

                    libc::cfmakeraw(&mut attrs as _);

                    if libc::tcsetattr(slave_fd, libc::TCSANOW, &attrs as _) != 0 {
                        return Err(IoErr::last_os_error());
                    }
                }

                // This is OK even though we don't own master since this process is
                // about to become something totally different anyway.
                if libc::close(master_fd) != 0 {
                    return Err(IoErr::last_os_error());
                }

                if libc::setsid() < 0 {
                    return Err(IoErr::last_os_error());
                }

                if libc::ioctl(0, libc::TIOCSCTTY, 1) != 0 {
                    return Err(IoErr::last_os_error());
                }

                Ok(())
            });
        }

        Ok(self.spawn()?)
    }
}

/// An extension trait for the `std::process::Command` type.
///
/// This trait provides new `spawn_pty_async` and `spawn_pty_async_raw`
/// methods that allow one to spawn a new process that is connected to the
/// current process through a pseudo-TTY.
pub trait PtyCommandExt {
    /// Spawn a subprocess that connects to the current one through a
    /// pseudo-TTY in canonical (“cooked“, not “raw”) mode.
    ///
    /// This function creates the necessary PTY slave and uses
    /// `std::process::Command::before_exec` to do the neccessary setup before
    /// the child process is spawned. In particular, it calls `setsid()` to
    /// launch a new TTY sesson.
    ///
    /// The child process’s standard input, standard output, and standard
    /// error are all connected to the pseudo-TTY slave.
    fn spawn_pty(&mut self, ptymaster: &PtyMaster) -> Result<Child, IoErr>;

    /// Spawn a subprocess that connects to the current one through a
    /// pseudo-TTY in raw (“non-canonical”, not “cooked”) mode.
    ///
    /// This function creates the necessary PTY slave and uses
    /// `std::process::Command::before_exec` to do the neccessary setup before
    /// the child process is spawned. In particular, it sets the slave PTY
    /// handle to raw mode and calls `setsid()` to launch a new TTY sesson.
    ///
    /// The child process’s standard input, standard output, and standard
    /// error are all connected to the pseudo-TTY slave.
    fn spawn_pty_raw(&mut self, ptymaster: &PtyMaster) -> Result<Child, IoErr>;
}

impl PtyCommandExt for process::Command {
    fn spawn_pty(&mut self, ptymaster: &PtyMaster) -> Result<Child, IoErr> {
        self.spawn_pty_full(ptymaster, false)
    }

    fn spawn_pty_raw(&mut self, ptymaster: &PtyMaster) -> Result<Child, IoErr> {
        self.spawn_pty_full(ptymaster, true)
    }
}
