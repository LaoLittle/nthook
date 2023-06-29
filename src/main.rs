mod native;
use native::{GetThreadContext, CONTEXT};

use std::borrow::Cow;
use std::collections::HashMap;
use std::env::current_dir;
use std::ffi::CStr;

use std::io::Write;
use std::mem::{size_of, size_of_val};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::{fs, io};
use termcolor::{ColorChoice, ColorSpec, StandardStream, WriteColor};
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, MAX_PATH, WORD};
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
use winapi::um::winnt::{CONTEXT_u, CONTEXT_FULL, DBG_EXCEPTION_NOT_HANDLED, M128A};
use winapi::um::winnt::{
    DBG_CONTINUE, DBG_EXCEPTION_HANDLED, HANDLE, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
    THREAD_GET_CONTEXT,
};

const WELCOME_INFO: &str = include_str!("../resources/welcome_info");
const MAX_PATH_BUF_SIZE: usize = MAX_PATH + 1;

const OFFSET: isize = 0x22b5f6f;

struct DebugInfo {
    exception: EXCEPTION_DEBUG_INFO,
    process: HANDLE,
    thread: HANDLE,
}

fn main() {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);
    stdout
        .set_color(&ColorSpec::new().set_fg(Some(termcolor::Color::Cyan)))
        .unwrap();
    stdout.write_all(WELCOME_INFO.as_bytes()).unwrap();
    stdout.write_all(b"\n").unwrap();
    stdout.reset().unwrap();
    stdout.flush().unwrap();

    drop(stdout);

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
                                let mut buf = 0u8;
                                let mut read = 0;

                                wrap(|| {
                                    ReadProcessMemory(
                                        process,
                                        info.ExceptionRecord.ExceptionAddress,
                                        (&mut buf) as *mut u8 as _,
                                        1,
                                        &mut read,
                                    )
                                })
                                .unwrap();

                                println!(
                                    "[NTHook][PID: {}][TID: {}][Address: {:p}] Breakpoint",
                                    event.dwProcessId,
                                    event.dwThreadId,
                                    info.ExceptionRecord.ExceptionAddress
                                );

                                break 'cs break_table
                                    .get(&(info.ExceptionRecord.ExceptionAddress as usize))
                                    .map(|f| {
                                        f(DebugInfo {
                                            exception: *info,
                                            process,
                                            thread,
                                        })
                                    })
                                    .unwrap_or(DBG_EXCEPTION_NOT_HANDLED);
                            }
                            _ => {}
                        }

                        DBG_EXCEPTION_NOT_HANDLED
                    }
                    LOAD_DLL_DEBUG_EVENT => {
                        //println!("Recv: {:?}, code={}", event.dwProcessId, event.dwDebugEventCode);
                        let info = event.u.LoadDll();

                        if !info.lpBaseOfDll.is_null() {
                            let mut buf = [0u8; MAX_PATH];

                            let mut common_len = 0;

                            let read = GetMappedFileNameW(
                                process,
                                info.lpBaseOfDll,
                                buf.as_mut_ptr() as _,
                                MAX_PATH as _,
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

                            if p.file_name().unwrap().to_str().unwrap() == "wrapper.node" {
                                println!("[PID: {}][LoadDLL] wrapper.node", event.dwProcessId);
                                let mut buf_byte = [0u8; 1];

                                let addr = info.lpBaseOfDll.offset(OFFSET);
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
                                    println!("[NTHook] set breakpoint {:p} in wrapper.node", addr);

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
                                    panic!("unable to set breakpoint in wrapper.node at 0x22b5f6f");
                                }
                            }
                        }

                        DBG_CONTINUE
                    }
                    CREATE_PROCESS_DEBUG_EVENT => {
                        let info = event.u.CreateProcessInfo();

                        println!(
                            "[NTHook][PID: {}] Process {} created.",
                            event.dwProcessId,
                            GetProcessId(info.hProcess)
                        );

                        DBG_CONTINUE
                    }
                    EXIT_PROCESS_DEBUG_EVENT => {
                        let info = event.u.ExitProcess();
                        println!(
                            "[NTHook][PID: {}] Process exit, ExitCode = 0x{:X}",
                            event.dwProcessId, info.dwExitCode
                        );

                        if event.dwProcessId == dbg_process_info.dwProcessId {
                            println!("[NTHoo] Main process killed, stop.");
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

        let mut stdout = StandardStream::stdout(ColorChoice::Auto);
        stdout
            .set_color(&ColorSpec::new().set_fg(Some(termcolor::Color::Cyan)))
            .unwrap();

        writeln!(
            stdout,
            "[NTHook-Log] {}",
            CStr::from_bytes_until_nul(&buf).unwrap().to_str().unwrap()
        )
        .unwrap();

        stdout.reset().unwrap();
        stdout.flush().unwrap();
    }

    DBG_EXCEPTION_HANDLED
}

fn wrap<F: FnOnce() -> i32>(f: F) -> io::Result<()> {
    if f() == FALSE {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
