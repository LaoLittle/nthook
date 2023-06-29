mod native;
use native::{GetThreadContext, CONTEXT};

use std::borrow::Cow;
use std::collections::HashMap;
use std::env::current_dir;
use std::ffi::CStr;

use std::io::Write;
use std::mem::{size_of, size_of_val, MaybeUninit};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use std::{fs, io, thread};
use termcolor::{ColorChoice, ColorSpec, StandardStream, WriteColor};
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH};
use winapi::um::debugapi::{ContinueDebugEvent, WaitForDebugEvent};

use winapi::um::handleapi::CloseHandle;

use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::minwinbase::{
    CREATE_PROCESS_DEBUG_EVENT, EXCEPTION_BREAKPOINT, EXCEPTION_DEBUG_EVENT, EXCEPTION_DEBUG_INFO,
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};
use winapi::um::processthreadsapi::{CreateProcessW, GetProcessId, OpenProcess, OpenThread};
use winapi::um::psapi::GetMappedFileNameW;

use winapi::um::winbase::{lstrlenW, DEBUG_PROCESS, INFINITE};
use winapi::um::wincon::SetConsoleOutputCP;
use winapi::um::winnt::{CONTEXT_FULL, DBG_EXCEPTION_NOT_HANDLED};
use winapi::um::winnt::{
    DBG_CONTINUE, DBG_EXCEPTION_HANDLED, HANDLE, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
};

macro_rules! log {
    () => {
        $crate::log!("")
    };
    ($($arg:tt)*) => {{
        use std::fmt::Write;

        #[allow(unused_unsafe)]
        unsafe {
            let mut s = String::new();
            writeln!(s, $($arg)*).unwrap();
            $crate::SENDER.assume_init_ref().send(Event::Log(s)).unwrap();
        }
    }};
}

const WELCOME_INFO: &str = include_str!("../resources/welcome_info");
const MAX_PATH_BUF_SIZE: usize = MAX_PATH + 1;

#[repr(C)]
struct DebugInfo {
    exception: EXCEPTION_DEBUG_INFO,
    process: HANDLE,
    thread: HANDLE,
}

enum Event {
    Log(String),
}

static mut SENDER: MaybeUninit<mpsc::Sender<Event>> = MaybeUninit::uninit();

fn main() {
    let (tx, rx) = mpsc::channel::<Event>();
    unsafe {
        SENDER.write(tx);
    }
    thread::spawn(move || {
        for event in rx {
            match event {
                Event::Log(s) => {
                    let mut stdout = StandardStream::stdout(ColorChoice::Auto);
                    stdout
                        .set_color(&ColorSpec::new().set_fg(Some(termcolor::Color::Cyan)))
                        .unwrap();
                    stdout.write_all(s.as_bytes()).unwrap();
                    stdout.reset().unwrap();
                    stdout.flush().unwrap();
                }
            }
        }
    });

    log!("{}", WELCOME_INFO);

    let p = Path::new("QQ.exe");

    let exec = if let Ok(meta) = fs::metadata(p) {
        if meta.is_file() {
            Cow::Borrowed("QQ.exe")
        } else {
            panic!("QQ.exe is not a file?");
        }
    } else {
        let mut path = std::env::args();
        let me = path.next().unwrap();
        let exec = path
            .next()
            .unwrap_or_else(|| panic!("参数缺失可执行文件路径, 使用 {} <File> 执行", me));

        Cow::Owned(exec)
    };

    let exec = if Path::new(&*exec).is_absolute() {
        exec
    } else {
        let mut s = current_dir().unwrap();
        s.push(&*exec);
        Cow::Owned(s.to_str().unwrap().to_string())
    };

    println!("Starting {}", exec);

    let mut enc = exec.encode_utf16().collect::<Vec<u16>>();
    enc.push(0);

    unsafe {
        SetConsoleOutputCP(65001);

        let flags = DEBUG_PROCESS;
        let mut dbg_startup_info = Default::default();
        let mut dbg_process_info = Default::default();

        wrap(|| {
            CreateProcessW(
                enc.as_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                0,
                flags,
                null_mut(),
                null(),
                &mut dbg_startup_info,
                &mut dbg_process_info,
            )
        })
        .unwrap();

        let mut break_table = HashMap::<usize, unsafe fn(DebugInfo) -> DWORD>::new();

        'main_loop: loop {
            let mut event = Default::default();

            wrap(|| WaitForDebugEvent(&mut event, INFINITE)).unwrap();

            //println!("Recv: {:?}, code={}", event.dwProcessId, event.dwDebugEventCode);

            let process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, event.dwProcessId);
            let thread = OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId);

            if process.is_null() {
                panic!("unable to get handle of process {}", event.dwProcessId);
            }

            if thread.is_null() {
                panic!(
                    "unable to get handle of thread {} in process {}",
                    event.dwThreadId, event.dwProcessId
                );
            }

            let cs = 'cs: {
                match event.dwDebugEventCode {
                    EXCEPTION_DEBUG_EVENT => {
                        let info = event.u.Exception();

                        match info.ExceptionRecord.ExceptionCode {
                            EXCEPTION_BREAKPOINT => {
                                break 'cs break_table
                                    .get(&(info.ExceptionRecord.ExceptionAddress as usize))
                                    .map(|f| {
                                        f(DebugInfo {
                                            exception: *info,
                                            process,
                                            thread,
                                        })
                                    })
                                    .unwrap_or_else(|| {
                                        log!(
                                    "[NTHook][PID: {}][TID: {}][Address: {:p}] Unknown breakpoint",
                                    event.dwProcessId,
                                    event.dwThreadId,
                                    info.ExceptionRecord.ExceptionAddress
                                );
                                        DBG_EXCEPTION_NOT_HANDLED
                                    });
                            }
                            _ => {}
                        }

                        DBG_EXCEPTION_NOT_HANDLED
                    }
                    LOAD_DLL_DEBUG_EVENT => {
                        let info = event.u.LoadDll();

                        if !info.lpBaseOfDll.is_null() {
                            let mut buf = [0u8; MAX_PATH_BUF_SIZE];

                            let mut common_len = 0;

                            let read = GetMappedFileNameW(
                                process,
                                info.lpBaseOfDll,
                                buf.as_mut_ptr() as _,
                                MAX_PATH_BUF_SIZE as DWORD,
                            );
                            let len = lstrlenW(buf.as_ptr() as _);

                            if read == 0 {
                                continue 'main_loop;
                            }

                            let driver_path = String::from_utf16(std::slice::from_raw_parts(
                                buf.as_mut_ptr() as _,
                                len as usize,
                            ))
                            .unwrap();

                            let p = Path::new(&driver_path);

                            //println!("[PID: {}][LoadDLL] {}", event.dwProcessId, p.file_name().unwrap().to_str().unwrap());

                            match p.file_name().unwrap().to_str().unwrap() {
                                "wrapper.node" => {
                                    log!("[PID: {}][LoadDLL] wrapper.node", event.dwProcessId);
                                    // nop replace
                                    let offsets = [0x22b5f6f, 0x1df46bf];

                                    for offset in offsets {
                                        let mut buf_byte = [0u8; 1];

                                        let addr = info.lpBaseOfDll.offset(offset);
                                        wrap(|| {
                                            ReadProcessMemory(
                                                process,
                                                addr,
                                                buf_byte.as_mut_ptr() as _,
                                                1,
                                                &mut common_len,
                                            )
                                        })
                                        .unwrap();

                                        let [byte] = buf_byte;

                                        if byte == 0x90 {
                                            log!(
                                                "[NTHook] set breakpoint {:p} in wrapper.node",
                                                addr
                                            );

                                            break_table.insert(addr as usize, get_log);

                                            //buf_byte = 0xCC;
                                            buf_byte = [0xCC];

                                            wrap(|| {
                                                WriteProcessMemory(
                                                    process,
                                                    addr,
                                                    buf_byte.as_ptr() as _,
                                                    1,
                                                    &mut common_len,
                                                )
                                            })
                                            .unwrap();
                                        } else {
                                            panic!(
                                                "unable to set breakpoint in wrapper.node at 0x22b5f6f"
                                            );
                                        }
                                    }

                                    let offset = 0x1e0d443;
                                    let mut buf_byte = [0u8; 1];

                                    let addr = info.lpBaseOfDll.offset(offset);
                                    wrap(|| {
                                        ReadProcessMemory(
                                            process,
                                            addr,
                                            buf_byte.as_mut_ptr() as _,
                                            1,
                                            &mut common_len,
                                        )
                                    })
                                    .unwrap();

                                    let [byte] = buf_byte;

                                    if byte == 0x90 {
                                        log!("[NTHook] set breakpoint {:p} in wrapper.node", addr);

                                        break_table.insert(addr as usize, get_log_r14);

                                        //buf_byte = 0xCC;
                                        buf_byte = [0xCC];

                                        wrap(|| {
                                            WriteProcessMemory(
                                                process,
                                                addr,
                                                buf_byte.as_ptr() as _,
                                                1,
                                                &mut common_len,
                                            )
                                        })
                                        .unwrap();
                                    } else {
                                        panic!(
                                            "unable to set breakpoint in wrapper.node at 0x22b5f6f"
                                        );
                                    }
                                    /*
                                    // ret replace
                                    let offsets = [0x23a60f8];

                                    for offset in offsets {
                                        let mut buf_byte = [0u8; 2];

                                        let addr = info.lpBaseOfDll.offset(offset);
                                        wrap(|| {
                                            ReadProcessMemory(
                                                process,
                                                addr,
                                                buf_byte.as_mut_ptr() as _,
                                                2,
                                                &mut common_len,
                                            )
                                        })
                                            .unwrap();

                                        if buf_byte == [0xC3, 0xCC] {
                                            log!(
                                                "[NTHook] set breakpoint {:p} in wrapper.node",
                                                addr
                                            );

                                            break_table.insert(addr as usize, nop);

                                            //buf_byte = 0xCC;
                                            buf_byte = [0xCC, 0xC3];

                                            wrap(|| {
                                                WriteProcessMemory(
                                                    process,
                                                    addr,
                                                    buf_byte.as_ptr() as _,
                                                    2,
                                                    &mut common_len,
                                                )
                                            })
                                                .unwrap();
                                        } else {
                                            panic!(
                                                "unable to set breakpoint in wrapper.node at 0x22b5f6f"
                                            );
                                        }
                                    }*/
                                }
                                _ => {}
                            }
                        }

                        DBG_CONTINUE
                    }
                    CREATE_PROCESS_DEBUG_EVENT => {
                        let info = event.u.CreateProcessInfo();

                        log!(
                            "[NTHook][PID: {}] Process {} created.",
                            event.dwProcessId,
                            GetProcessId(info.hProcess)
                        );

                        DBG_CONTINUE
                    }
                    EXIT_PROCESS_DEBUG_EVENT => {
                        let info = event.u.ExitProcess();
                        log!(
                            "[NTHook][PID: {}] Process exit, ExitCode = 0x{:X}",
                            event.dwProcessId,
                            info.dwExitCode
                        );

                        if event.dwProcessId == dbg_process_info.dwProcessId {
                            log!("[NTHoo] Main process killed, stop.");
                            std::process::exit(info.dwExitCode as _);
                        }

                        DBG_CONTINUE
                    }
                    _ => DBG_CONTINUE,
                }
            };

            wrap(|| CloseHandle(process)).unwrap();
            wrap(|| CloseHandle(thread)).unwrap();

            wrap(|| ContinueDebugEvent(event.dwProcessId, event.dwThreadId, cs)).unwrap();
        }
    }
}

unsafe fn get_log_r15(
    DebugInfo {
        exception: _,
        process,
        thread,
    }: DebugInfo,
) -> DWORD {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_FULL;

    wrap(|| GetThreadContext(thread, &mut ctx)).unwrap();

    let addr = ctx.R15;
    if addr != 0 {
        let mut read = 0;
        let mut ptr = 0usize;

        wrap(|| {
            ReadProcessMemory(
                process,
                addr as _,
                (&mut ptr) as *mut usize as _,
                size_of::<usize>(),
                &mut read,
            )
        })
        .unwrap();

        let mut buf = [0; 1024];

        let _ = wrap(|| {
            ReadProcessMemory(
                process,
                ptr as _,
                buf.as_mut_ptr() as _,
                size_of_val(&buf),
                &mut read,
            )
        });

        log!(
            "[NTHook-Log] {}",
            CStr::from_bytes_until_nul(&buf).unwrap().to_str().unwrap()
        );
    }

    DBG_EXCEPTION_HANDLED
}

unsafe fn get_log_r14(
    DebugInfo {
        exception: _,
        process,
        thread,
    }: DebugInfo,
) -> DWORD {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_FULL;

    wrap(|| GetThreadContext(thread, &mut ctx)).unwrap();

    let addr = ctx.R14;
    if addr != 0 {
        let mut read = 0;
        let mut buf = [0u8; 8192];

        let _ = wrap(|| {
            ReadProcessMemory(
                process,
                addr as _,
                buf.as_mut_ptr() as _,
                buf.len(),
                &mut read,
            )
        });

        let mut heap;

        let str = if let Some(idx) = memchr::memchr(0, &buf) {
            String::from_utf8_lossy(&buf[..idx])
        } else {
            let mut len = buf.len();
            heap = Vec::<u8>::with_capacity(buf.len() << 1);
            heap.extend_from_slice(&buf);

            loop {
                if wrap(|| {
                    ReadProcessMemory(
                        process,
                        (addr as usize + len) as _,
                        buf.as_mut_ptr() as _,
                        buf.len(),
                        &mut read,
                    )
                })
                .is_err()
                {
                    break;
                }

                heap.extend_from_slice(&buf);

                match memchr::memchr(0, &buf) {
                    Some(idx) => {
                        len += idx;
                        break;
                    }
                    None => len += buf.len(),
                }
            }

            heap.truncate(len);
            String::from_utf8_lossy(&heap)
        };

        log!("[NTHook-Log] {}", str);

        /*if let Ok(cstr) = CStr::from_bytes_until_nul(&buf) {
            log!("[NTHook-Log] {}",cstr.to_str().unwrap());
        } else {
            log!("[NTHook-Log] Buffer = {:?}", buf);
        }*/
    }

    DBG_EXCEPTION_HANDLED
}

unsafe fn get_log(
    DebugInfo {
        exception: _,
        process,
        thread,
    }: DebugInfo,
) -> DWORD {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_FULL;

    wrap(|| GetThreadContext(thread, &mut ctx)).unwrap();

    let addr = ctx.Rax;
    if addr != 0 {
        let mut read = 0;
        let mut ptr = 0usize;

        wrap(|| {
            ReadProcessMemory(
                process,
                addr as _,
                (&mut ptr) as *mut usize as _,
                size_of::<usize>(),
                &mut read,
            )
        })
        .unwrap();

        let mut buf = [0; 1024];

        let _ = wrap(|| {
            ReadProcessMemory(
                process,
                ptr as _,
                buf.as_mut_ptr() as _,
                size_of_val(&buf),
                &mut read,
            )
        });

        log!(
            "[NTHook-Log] {}",
            CStr::from_bytes_until_nul(&buf).unwrap().to_str().unwrap()
        );
    }

    DBG_EXCEPTION_HANDLED
}

unsafe fn nop(_: DebugInfo) -> DWORD {
    DBG_EXCEPTION_HANDLED
}

fn wrap<F: FnOnce() -> i32>(f: F) -> io::Result<()> {
    if f() == FALSE {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
