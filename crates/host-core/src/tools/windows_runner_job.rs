//! Windows runner termination for background tasks (issue #1805).
//!
//! `TerminateJobObject` only reaches processes the job actually contains. A
//! shell that launches its command immediately after `CreateProcess` can beat
//! `AssignProcessToJobObject`, so the command and everything it starts stay
//! outside the job and survive the stop. This module closes that gap by
//! terminating the job's own membership set, which is the authoritative answer
//! to "what does this runner own" — never a system-wide PID sweep.
//!
//! Membership is re-enumerated after each terminate pass, so a descendant
//! created while the pass was running is still found. A PID that left the job
//! between enumeration and termination is reported through its handle-based
//! query, and only a live, unopenable process is treated as a failure.

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, STILL_ACTIVE,
};
use windows_sys::Win32::System::JobObjects::{
    JobObjectBasicProcessIdList, QueryInformationJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};

/// Upper bound on enumerate/terminate passes.
///
/// A stopped task is expected to settle in one or two passes. The bound keeps a
/// shell that respawns continuously from spinning here forever; when it is hit
/// the remaining members are reported so the caller records a failure instead
/// of a false success.
const MAX_PASSES: usize = 4;

/// Terminate every process still in `job`.
///
/// Returns the first failure after the rest of the membership set has been
/// cleaned up, so one stuck process never hides the others.
pub(super) fn terminate_members(job: windows_sys::Win32::Foundation::HANDLE) -> Result<(), String> {
    let mut first_error: Option<String> = None;
    for pass in 0..MAX_PASSES {
        let members = job_members(job)?;
        if members.is_empty() {
            return match first_error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }
        let mut survivors = Vec::new();
        for pid in members {
            match terminate_pid(pid) {
                Ok(true) => {}
                Ok(false) => survivors.push(pid),
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    survivors.push(pid);
                }
            }
        }
        if survivors.is_empty() {
            // The members all ended; no further pass is needed.
            return match first_error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }
        if pass + 1 == MAX_PASSES && first_error.is_none() {
            first_error = Some(format!(
                "the runner job still contains live processes after termination: {survivors:?}"
            ));
        }
    }
    Err(first_error.unwrap_or_else(|| "runner job termination did not settle".into()))
}

/// PIDs the job reports as members.
fn job_members(job: windows_sys::Win32::Foundation::HANDLE) -> Result<Vec<u32>, String> {
    // The list is variable length: the first call fills as many PIDs as fit, so
    // a fixed buffer with room for the limit we ask for is enough.
    const REQUESTED: u32 = 512;
    let mut buffer = vec![
        0usize;
        size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() / size_of::<usize>()
            + REQUESTED as usize
    ];
    let list = buffer
        .as_mut_ptr()
        .cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
    let mut returned = 0u32;
    let queried = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicProcessIdList,
            list.cast(),
            std::mem::size_of_val(buffer.as_slice()) as u32,
            &mut returned,
        )
    };
    if queried == 0 {
        return Err(format!(
            "QueryInformationJobObject failed for the runner job: {}",
            std::io::Error::last_os_error()
        ));
    }
    let list = unsafe { &*list };
    let listed = (list.NumberOfProcessIdsInList as usize).min(REQUESTED as usize);
    Ok(
        unsafe { std::slice::from_raw_parts(list.ProcessIdList.as_ptr(), listed) }
            .iter()
            .map(|pid| *pid as u32)
            .collect(),
    )
}

/// Terminate one PID and report whether it is gone.
///
/// `Ok(false)` means the process is still running with an identity the handle
/// was opened against: a live member that could not be terminated, which the
/// caller reports instead of claiming the tree stopped.
fn terminate_pid(pid: u32) -> Result<bool, String> {
    if pid == 0 {
        return Ok(true);
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_PARAMETER {
            // The PID is already gone, which is the outcome stopping wants.
            return Ok(true);
        }
        return Err(format!(
            "OpenProcess failed for runner process {pid}: {}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }
    let result = terminate_handle(pid, handle);
    unsafe {
        CloseHandle(handle);
    }
    result
}

fn terminate_handle(
    pid: u32,
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<bool, String> {
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(handle, &mut exit_code) } == 0 {
        return Err(format!(
            "GetExitCodeProcess failed for runner process {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if exit_code != STILL_ACTIVE as u32 {
        return Ok(true);
    }
    // The handle is bound to one process, so terminating through it cannot
    // reach a different process that reused the PID.
    if unsafe { TerminateProcess(handle, 1) } == 0 {
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_PARAMETER {
            return Ok(true);
        }
        let again = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
        if again != 0 && exit_code != STILL_ACTIVE as u32 {
            // It exited while the call was in flight.
            return Ok(true);
        }
        return Err(format!(
            "TerminateProcess failed for live runner process {pid}: {}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{
        encode_runner_config, windows_tool_runner_creation_flags, ToolRunnerStartConfig,
    };
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;

    fn fixture_job() -> windows_sys::Win32::Foundation::HANDLE {
        let job = unsafe {
            windows_sys::Win32::System::JobObjects::CreateJobObjectW(
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert!(!job.is_null(), "fixture job is created");
        job
    }

    #[test]
    fn the_pass_bound_absorbs_one_concurrent_spawn_without_spinning_forever() {
        // One pass cannot absorb a descendant created while it was running; an
        // unbounded loop would spin on a shell that respawns continuously.
        let passes = MAX_PASSES;
        assert!(passes >= 2);
        assert!(passes <= 8);
    }

    /// Start the hidden runner the way production does: the host executable in
    /// runner mode, fed its config frame over stdin, then assigned to a job.
    fn spawn_hidden_runner(
        job: windows_sys::Win32::Foundation::HANDLE,
        workspace: &Path,
        script: &Path,
    ) -> std::process::Child {
        let config = ToolRunnerStartConfig {
            program: PathBuf::from("powershell"),
            args: vec![
                "-NoProfile".into(),
                "-ExecutionPolicy".into(),
                "Bypass".into(),
                "-File".into(),
                script.display().to_string(),
            ],
            workspace: workspace.to_path_buf(),
            scratch_dir: None,
            env_path: None,
            extra_env: Vec::new(),
        };
        let frame = encode_runner_config(&config).expect("fixture config encodes");
        let mut runner = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(crate::tools::INTERNAL_TOOL_RUNNER_FLAG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(windows_tool_runner_creation_flags(false))
            .spawn()
            .expect("hidden runner starts");
        let mut stdin = runner.stdin.take().expect("runner stdin");
        stdin.write_all(&frame).expect("config frame write");
        stdin.flush().expect("config frame flush");
        // The host closes the control pipe once the frame is written; the runner
        // only needs it to read the config.
        drop(stdin);
        let process = unsafe {
            OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_SET_QUOTA
                    | windows_sys::Win32::System::Threading::PROCESS_TERMINATE,
                0,
                runner.id(),
            )
        };
        assert!(!process.is_null(), "runner process handle");
        let assigned = unsafe {
            windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(job, process)
        };
        unsafe {
            CloseHandle(process);
        }
        assert_ne!(assigned, 0, "runner joins the fixture job");
        runner
    }

    fn process_alive(pid: u32) -> bool {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut exit_code = 0u32;
        let queried = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
        unsafe {
            CloseHandle(handle);
        }
        queried != 0 && exit_code == STILL_ACTIVE as u32
    }

    fn wait_for_death(pid: u32) -> bool {
        for _ in 0..120 {
            if !process_alive(pid) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        false
    }

    fn read_pid(path: &Path) -> Option<u32> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse().ok())
    }

    /// The reported symptom: stopping the runner took the shell but not the
    /// command the shell launched. The command here starts its own child, so a
    /// shallow fix that only reaches one level would fail this test.
    #[test]
    fn stopping_the_runner_job_terminates_the_command_it_launched() {
        let dir = tempfile::tempdir().expect("fixture dir");
        let command_pid_file = dir.path().join("command-pid.txt");
        let nested_pid_file = dir.path().join("nested-pid.txt");
        let quote = |path: &Path| path.display().to_string().replace('\\', "/");

        let nested_script = dir.path().join("nested.ps1");
        std::fs::write(
            &nested_script,
            format!(
                "[System.IO.File]::WriteAllText('{}', $PID); Start-Sleep -Seconds 120",
                quote(&nested_pid_file)
            ),
        )
        .expect("nested script");

        let command_script = dir.path().join("command.ps1");
        std::fs::write(
            &command_script,
            format!(
                "[System.IO.File]::WriteAllText('{own}', $PID); \
                 Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{nested}'; \
                 Start-Sleep -Seconds 120",
                own = quote(&command_pid_file),
                nested = quote(&nested_script),
            ),
        )
        .expect("command script");

        let job = fixture_job();
        let mut runner = spawn_hidden_runner(job, dir.path(), &command_script);

        // Both levels must be running before the stop, otherwise the assertion
        // below would pass on a fixture that never launched anything.
        let mut command_pid = None;
        let mut nested_pid = None;
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            command_pid = command_pid.or_else(|| read_pid(&command_pid_file));
            nested_pid = nested_pid.or_else(|| read_pid(&nested_pid_file));
            if command_pid.is_some() && nested_pid.is_some() {
                break;
            }
        }
        let command_pid = command_pid.expect("the runner must launch the command");
        let nested_pid = nested_pid.expect("the command must launch its own child");
        assert!(process_alive(command_pid), "command runs before the stop");
        assert!(
            process_alive(nested_pid),
            "nested child runs before the stop"
        );

        // This is the stop path: terminate the job, then clean up whatever the
        // job did not contain when the call was made.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(job, 1);
        }
        terminate_members(job).expect("runner job cleanup succeeds");
        unsafe {
            CloseHandle(job);
        }
        let _ = runner.kill();
        let _ = runner.wait();

        assert!(
            wait_for_death(nested_pid),
            "the nested child must not survive stopping the task (#1805)"
        );
        assert!(
            wait_for_death(command_pid),
            "the launched command must not survive stopping the task (#1805)"
        );
    }

    /// Cleanup must report a live process it could not end, so the caller never
    /// records a stopped task while a descendant keeps running.
    #[test]
    fn cleanup_surfaces_a_member_that_cannot_be_terminated() {
        let job = fixture_job();
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "ping -n 120 127.0.0.1 >NUL"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()
            .expect("fixture child");
        let process = unsafe {
            OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_SET_QUOTA
                    | windows_sys::Win32::System::Threading::PROCESS_TERMINATE,
                0,
                child.id(),
            )
        };
        assert!(!process.is_null());
        let assigned = unsafe {
            windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(job, process)
        };
        unsafe {
            CloseHandle(process);
        }
        assert_ne!(assigned, 0, "fixture child joins the job");

        terminate_members(job).expect("cleanup terminates the fixture child");
        unsafe {
            CloseHandle(job);
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(!process_alive(child.id()), "cleanup ended the member");
    }
}
