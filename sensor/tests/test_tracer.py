from tracer import strip_root_execve

MULTI_LINE_TRACE = (
    '12345 execve("/bin/bash", ["bash", "/tmp/sample.sh"], 0x7fff /* 20 vars */) = 0\n'
    '12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3\n'
    '12346 execve("/usr/bin/touch", ["touch", "/etc/mirraura-test-marker"], 0x7fff /* 20 vars */) = 0\n'
)

ONLY_ROOT_TRACE = (
    '12345 execve("/bin/bash", ["bash", "/tmp/sample.sh"], 0x7fff /* 20 vars */) = 0\n'
)

NO_EXECVE_TRACE = (
    '12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3\n'
    '12346 connect(3, {sa_family=AF_INET, sin_port=htons(31337), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED\n'
)


def test_strips_only_the_leading_root_execve_line():
    result = strip_root_execve(MULTI_LINE_TRACE)
    remaining = result.splitlines(keepends=True)
    original = MULTI_LINE_TRACE.splitlines(keepends=True)
    assert remaining == original[1:]


def test_only_root_execve_line_results_in_empty_string():
    assert strip_root_execve(ONLY_ROOT_TRACE) == ""


def test_empty_string_returns_empty_string():
    assert strip_root_execve("") == ""


def test_no_execve_line_leaves_everything_untouched():
    assert strip_root_execve(NO_EXECVE_TRACE) == NO_EXECVE_TRACE
