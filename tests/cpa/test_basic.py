# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


import subprocess

import pytest

from .conftest import run_command


def _write_invalid_btf(tmp_path):
    bad_btf = tmp_path / "invalid.btf"
    bad_btf.write_text("not-a-btf-file\n", encoding="utf-8")
    return bad_btf


def test_cpa_exits_when_no_args() -> None:
    p = subprocess.run(
        ["./build/bin/cpa"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=3,
    )
    assert p.returncode != 0
    assert "usage" in (p.stdout + p.stderr).lower()


def test_cpa_monitor_startup_failure_is_reported(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--freq=1",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}"
    assert return_code != 0
    assert "Failed to init worker perf_capture_worker" in full_output
    assert "Failed to join timer_thread, thread not created" not in full_output


def test_cpa_monitor_bench_reports_dwarf_unwind_stats(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--freq=49",
            "--duration=2",
            "--store_dir",
            str(tmp_path),
            "--bench",
            "--log_print_cycles=1",
        ],
        timeout=20,
    )

    full_output = f"{stdout}{stderr}"
    assert return_code == 0, full_output
    assert "Bench DWARF Unwind:" in full_output
    assert "rate=" in full_output
    assert "avg=" in full_output
    assert "min=" in full_output
    assert "max=" in full_output
    assert "Bench DWARF Histogram:" in full_output


@pytest.mark.parametrize(
    "extra_args, oncpu",
    [
        (["--offcpu"], "0"),
        (["--oncpu", "--offcpu"], "1"),
    ],
)
def test_cpa_monitor_perf_offcpu_writes_us_store(tmp_path, extra_args, oncpu):
    # perf --offcpu alone collects off-CPU only; --oncpu adds on-CPU to the store
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            *extra_args,
            "--freq=49",
            "--duration=2",
            "--store_dir",
            str(tmp_path),
        ]
    )

    assert return_code == 0, f"{stdout}{stderr}"
    confs = list(tmp_path.glob("cpa_*/conf"))
    assert confs
    conf = confs[0].read_text(encoding="utf-8")
    assert "count_unit: us" in conf
    assert f"oncpu: {oncpu}" in conf
    assert "offcpu_period: 100" in conf


def test_cpa_monitor_rejects_oncpu_and_offcpu_on_bpf_backend(tmp_path):
    stdout, stderr, return_code = run_command(
        ["monitor", "--backend=bpf", "--oncpu", "--offcpu", "--duration=1", "--store_dir", str(tmp_path)]
    )

    assert return_code != 0
    assert "use --backend perf" in f"{stdout}{stderr}"


@pytest.mark.parametrize(
    "probe",
    [
        "kprobe:try_to_free_pages",
        "kretprobe:try_to_free_pages",
        "tracepoint:sched:sched_process_exit",
    ],
)
def test_cpa_monitor_perf_backend_with_probe(tmp_path, probe):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            f"--probe={probe}",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    assert return_code == 0, f"{stdout}{stderr}"


@pytest.mark.parametrize(
    "extra_args, message",
    [
        (["--probe=uprobe:/bin/true:main"], "invalid probe"),
        (["--probe=tracepoint:sched"], "invalid probe"),
        (["--probe=kprobe:try_to_free_pages", "--offcpu"], "cannot be combined with --offcpu"),
    ],
)
def test_cpa_monitor_perf_backend_rejects_bad_probe(tmp_path, extra_args, message):
    stdout, stderr, return_code = run_command(
        ["monitor", "--backend=perf", "--duration=1", "--store_dir", str(tmp_path), *extra_args]
    )

    assert return_code != 0
    assert message in f"{stdout}{stderr}".lower()


def test_cpa_monitor_falls_back_to_perf_when_bpf_prereqs_missing(tmp_path):
    invalid_btf = _write_invalid_btf(tmp_path)

    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bpf",
            "--freq=49",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            f"--btf_path={invalid_btf}",
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code == 0
    assert "warning" in full_output
    assert "falling back to perf" in full_output
    assert "irqoff" in full_output


def test_cpa_monitor_rejects_bpf_only_offcpu_when_bpf_prereqs_missing(tmp_path):
    invalid_btf = _write_invalid_btf(tmp_path)

    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bpf",
            "--offcpu",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            f"--btf_path={invalid_btf}",
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "requires bpf backend" in full_output
    assert "cannot fall back to perf" in full_output


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--pid=1"],
    ],
)
def test_cpa_monitor_rejects_other_bpf_only_modes_when_bpf_prereqs_missing(tmp_path, extra_args):
    invalid_btf = _write_invalid_btf(tmp_path)

    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bpf",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            f"--btf_path={invalid_btf}",
            *extra_args,
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "requires bpf backend" in full_output
    assert "cannot fall back to perf" in full_output


def test_cpa_monitor_accepts_null_btf_path_as_default_btf(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bpf",
            "--freq=49",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            "--btf_path=null",
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code == 0
    assert "custom btf path null is not readable" not in full_output


def test_cpa_monitor_rejects_invalid_backend_value(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bogus",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "backend" in full_output
    assert "bpf or perf" in full_output


def test_cpa_monitor_rejects_non_positive_persistent_day(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--persistent_day=0",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code != 0
    assert "persistent_day" in full_output
    assert ("> 0" in full_output) or ("greater than 0" in full_output)


def test_cpa_monitor_perf_backend_oneshot_writes_profile(tmp_path):
    output = tmp_path / "cpa.prof"
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--oneshot",
            "--duration=2",
            "--output_prof",
            str(output),
        ]
    )

    assert return_code == 0, f"{stdout}{stderr}"
    assert output.exists()


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--comm=test-proc"],
        ["--kernel_stack"],
        ["--stack_size=16384"],
    ],
)
def test_cpa_monitor_accepts_perf_backend_with_bpf_aligned_options(tmp_path, extra_args):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            *extra_args,
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code == 0, full_output
    assert "requires bpf backend" not in full_output


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--kernel_stack"],
        ["--oneshot", "--output_prof", "cpa.prof"],
        ["--probe=kprobe:try_to_free_pages"],
    ],
)
def test_cpa_monitor_bpf_aligned_modes_fall_back_to_perf(tmp_path, extra_args):
    invalid_btf = _write_invalid_btf(tmp_path)

    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=bpf",
            "--duration=1",
            "--store_dir",
            str(tmp_path),
            f"--btf_path={invalid_btf}",
            *extra_args,
        ],
        cwd=str(tmp_path),
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code == 0, full_output
    assert "falling back to perf" in full_output


def test_cpa_monitor_accepts_perf_backend_with_pid(tmp_path):
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--freq=49",
            "--duration=1",
            "--pid=1",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}".lower()
    assert return_code == 0
    assert "require bpf backend" not in full_output


def test_cpa_monitor_store_limit_above_2gb_does_not_restart_loop(tmp_path):
    # 7168 MB / 3 days = 2389 MB per directory, which used to overflow int
    stdout, stderr, return_code = run_command(
        [
            "monitor",
            "--backend=perf",
            "--freq=49",
            "--duration=3",
            "--persistent_day=3",
            "--store_dir",
            str(tmp_path),
        ]
    )

    full_output = f"{stdout}{stderr}"
    assert return_code == 0
    assert full_output.count("set dir to") == 1


def test_cpa_monitor_rejects_perf_cgroup_on_bpf_backend(tmp_path):
    stdout, stderr, return_code = run_command(
        ["monitor", "--backend=bpf", "--perf_cgroup=auto", "--duration=1", "--store_dir", str(tmp_path)]
    )

    assert return_code != 0
    assert "--perf_cgroup requires --backend perf" in f"{stdout}{stderr}"


def test_cpa_show_rejects_invalid_target_state(tmp_path):
    stdout, stderr, return_code = run_command(
        ["show", "--read", str(tmp_path), "--target_state=idle"]
    )

    assert return_code != 0
    assert "target_state" in f"{stdout}{stderr}"


@pytest.mark.parametrize(
    "extra_args, stack_size",
    [
        ([], "61440"),
        (["--stack_size=8192"], "8192"),
    ],
)
def test_cpa_monitor_perf_stack_size_defaults_to_perf_limit(tmp_path, extra_args, stack_size):
    stdout, stderr, return_code = run_command(
        ["monitor", "--backend=perf", "--duration=1", "--store_dir", str(tmp_path), *extra_args]
    )

    assert return_code == 0, f"{stdout}{stderr}"
    confs = list(tmp_path.glob("cpa_*/conf"))
    assert confs
    assert f"stack_size: {stack_size}" in confs[0].read_text(encoding="utf-8")
