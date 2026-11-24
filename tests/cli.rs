//! Smoke tests of the built program. None of them changes the system: help,
//! version and argument errors are answered before elevation or any setup.
//! CI also takes the program built for these tests for its later checks.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_antigravity-bypass-russia"))
        .args(args)
        .output()
        .expect("the program starts")
}

#[test]
fn help_lists_the_main_commands() {
    let output = run(&["--help"]);
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8_lossy(&output.stdout);
    for command in ["unlock", "rollback", "status", "diagnostics", "report"] {
        assert!(help.contains(command), "--help does not mention {command}");
    }
}

#[test]
fn version_matches_the_package() {
    let output = run(&["--version"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        concat!("antigravity-bypass-russia v", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_commands_and_extra_arguments_are_refused() {
    for (args, message) in [
        (&["--no-such-command"][..], "Неизвестная команда"),
        (&["status", "extra"][..], "Лишние аргументы"),
        (&["", "extra"][..], "Лишние аргументы"),
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{args:?}: {output:?}"
        );
    }
}
