"""Render the synthetic diligence-call fixture to WAV.

Parses fixtures/interviews/brightwater_cto_interview_script.md, renders
each turn with macOS `say`, joins turns with 0.7s of silence via ffmpeg
into a 16 kHz mono 16-bit PCM WAV, and writes a turn->speaker sidecar
JSON for eval. Requires macOS `say` and ffmpeg on PATH.
"""

import argparse
import json
import re
import shutil
import subprocess
import tempfile
import wave
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_MD = ROOT / "fixtures/interviews/brightwater_cto_interview_script.md"
OUT_WAV = ROOT / "fixtures/interviews/brightwater_cto_interview.wav"
OUT_SIDECAR = ROOT / "fixtures/interviews/brightwater_cto_interview.speakers.json"

TURN_RE = re.compile(r"^\*\*(.+?):\*\*\s*(.*)$")
LEAD_NAME = "Diligence Lead"
DANA_NAME = "Dana"
SILENCE_SECONDS = 0.7
SAMPLE_RATE = 16000


def parse_turns(path: Path) -> list[dict[str, str]]:
    """Extract spoken turns in order; skip headers, notes, and tips."""
    turns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ">", "-")):
            continue
        match = TURN_RE.match(stripped)
        if not match:
            continue
        speaker, text = match.group(1).strip(), match.group(2).strip()
        if speaker == "Speakers" or not text:
            continue
        if speaker not in (LEAD_NAME, DANA_NAME):
            raise ValueError(
                f"Unknown speaker {speaker!r} in {path.name}; "
                f"want {LEAD_NAME!r} or {DANA_NAME!r}."
            )
        turns.append({"speaker": speaker, "text": text.replace("*", "")})
    if not turns:
        raise ValueError(f"No turns parsed from {path}.")
    return turns


def check_voice(name: str) -> None:
    out = subprocess.run(
        ["say", "-v", "?"], capture_output=True, text=True, check=True
    ).stdout
    installed = {line.split()[0] for line in out.splitlines() if line.strip()}
    if name not in installed:
        raise SystemExit(
            f"error: voice {name!r} is not installed "
            "(System Settings > Accessibility > Spoken Content > System Voice, "
            "or override with --lead-voice/--dana-voice)."
        )


def render_turn(voice: str, text: str, aiff_path: Path) -> None:
    subprocess.run(
        ["say", "-v", voice, "-o", str(aiff_path), text], check=True
    )


def to_wav(aiff_path: Path, wav_path: Path) -> None:
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-v",
            "error",
            "-i",
            str(aiff_path),
            "-ar",
            str(SAMPLE_RATE),
            "-ac",
            "1",
            "-acodec",
            "pcm_s16le",
            str(wav_path),
        ],
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lead-voice", default="Daniel")
    parser.add_argument("--dana-voice", default="Samantha")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and print turns without rendering audio.",
    )
    args = parser.parse_args()

    turns = parse_turns(SCRIPT_MD)
    print(f"parsed {len(turns)} turns from {SCRIPT_MD.name}")
    if args.dry_run:
        for index, turn in enumerate(turns, start=1):
            print(f"  {index:2d}. {turn['speaker']}: {turn['text'][:70]}")
        return 0

    for tool in ("say", "ffmpeg"):
        if shutil.which(tool) is None:
            raise SystemExit(
                f"error: {tool} not found on PATH"
                + (" (brew install ffmpeg)" if tool == "ffmpeg" else "")
                + "."
            )
    voices = {LEAD_NAME: args.lead_voice, DANA_NAME: args.dana_voice}
    check_voice(args.lead_voice)
    check_voice(args.dana_voice)

    with tempfile.TemporaryDirectory(prefix="synthetic_interview_") as tmp:
        tmpdir = Path(tmp)
        turn_wavs = []
        for index, turn in enumerate(turns):
            aiff_path = tmpdir / f"turn_{index:02d}.aiff"
            wav_path = tmpdir / f"turn_{index:02d}.wav"
            print(f"[{index + 1}/{len(turns)}] {turn['speaker']} ...")
            render_turn(voices[turn["speaker"]], turn["text"], aiff_path)
            to_wav(aiff_path, wav_path)
            turn_wavs.append(wav_path)
        silence = tmpdir / "silence.wav"
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-v",
                "error",
                "-f",
                "lavfi",
                "-i",
                f"anullsrc=r={SAMPLE_RATE}:cl=mono",
                "-t",
                str(SILENCE_SECONDS),
                "-acodec",
                "pcm_s16le",
                str(silence),
            ],
            check=True,
        )
        list_path = tmpdir / "concat.txt"
        parts = []
        for index, wav_path in enumerate(turn_wavs):
            parts.append(f"file '{wav_path}'")
            if index < len(turn_wavs) - 1:
                parts.append(f"file '{silence}'")
        list_path.write_text("\n".join(parts) + "\n", encoding="utf-8")
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-v",
                "error",
                "-f",
                "concat",
                "-safe",
                "0",
                "-i",
                str(list_path),
                "-c",
                "copy",
                str(OUT_WAV),
            ],
            check=True,
        )

    OUT_SIDECAR.write_text(
        json.dumps(
            {
                "voices": voices,
                "turns": [
                    {"turn": index, "speaker": turn["speaker"]}
                    for index, turn in enumerate(turns, start=1)
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    with wave.open(str(OUT_WAV), "rb") as wav:
        duration = wav.getnframes() / wav.getframerate()
        params = wav.getparams()
    assert (params.framerate, params.nchannels, params.sampwidth) == (16000, 1, 2)
    print(f"wrote {OUT_WAV.relative_to(ROOT)} ({duration:.1f}s)")
    print(f"wrote {OUT_SIDECAR.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
