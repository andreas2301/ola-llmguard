import pathlib
import re

REQ = pathlib.Path(__file__).resolve().parent.parent / "requirements.txt"


def _lines():
    return [
        line.strip()
        for line in REQ.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_no_cuda_pins():
    offenders = [line for line in _lines() if re.match(r"(?i)^cuda-", line)]
    assert not offenders, f"CUDA pins must not ship in a CPU-only image: {offenders}"


def test_cpu_torch_posture():
    text = REQ.read_text()
    assert "https://download.pytorch.org/whl/cpu" in text
    torch_lines = [line for line in _lines() if re.match(r"(?i)^torch==", line)]
    assert torch_lines and all("+cpu" in line for line in torch_lines), torch_lines


def test_no_nvidia_cuda_wheels():
    offenders = [line for line in _lines() if re.match(r"(?i)^nvidia-cu", line)]
    assert not offenders, offenders
