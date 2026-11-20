"""Leitura incremental de arquivos Zeek com confirmação persistente da posição."""

import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass
from hashlib import sha256
from os import fstat, replace
from pathlib import Path
from tempfile import NamedTemporaryFile
from types import TracebackType
from typing import BinaryIO, Self

from import_zeek import (
    BATCH_SIZE,
    MAX_LINE_BYTES,
    ConnectionMetadata,
    metadata_from_line,
)

ANCHOR_BYTES = 256


@dataclass(frozen=True)
class FilePosition:
    device: int
    inode: int
    offset: int
    anchor: str


def open_log(path: Path) -> BinaryIO:
    if os.name != "nt":
        return path.open("rb")

    # Permite que o produtor renomeie o log aberto durante a rotação no Windows.
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    generic_read = 0x80000000
    share_read_write_delete = 0x00000007
    open_existing = 3
    normal_file = 0x00000080
    handle = create_file(str(path), generic_read, share_read_write_delete, None, open_existing, normal_file, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError:
        close_handle = kernel.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        close_handle(handle)
        raise
    return os.fdopen(descriptor, "rb")


def file_position(stream: BinaryIO, offset: int) -> FilePosition:
    info = fstat(stream.fileno())
    anchor_start = max(0, offset - ANCHOR_BYTES)
    stream.seek(0, os.SEEK_END)
    stream.seek(anchor_start)
    anchor = sha256(stream.read(offset - anchor_start)).hexdigest()
    stream.seek(offset)
    return FilePosition(info.st_dev, info.st_ino, offset, anchor)


def state_path(directory: Path, api_origin: str, source_id: str, log: Path) -> Path:
    identity = "\n".join((api_origin, source_id, str(log.absolute())))
    return directory / f"{sha256(identity.encode('utf-8')).hexdigest()}.json"


def read_position(path: Path) -> FilePosition | None:
    try:
        with path.open("rb") as saved:
            data = json.loads(saved.read(4096))
        position = FilePosition(**data)
        if type(position.offset) is int and position.offset >= 0:
            return position
    except (OSError, ValueError, TypeError):
        return None
    return None


def save_position(path: Path, position: FilePosition) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as temporary:
            pending = Path(temporary.name)
            json.dump(asdict(position), temporary)
        replace(pending, path)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)


class ZeekFileCollector:
    """Mantém o arquivo aberto para drenar o inode antigo durante uma rotação."""

    def __init__(self, log: Path, checkpoint: Path) -> None:
        self.log = log
        self.checkpoint = checkpoint
        self.stream: BinaryIO | None = None
        self.confirmed = read_position(checkpoint)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.stream is not None:
            self.stream.close()

    def _open_if_needed(self) -> BinaryIO:
        if self.stream is None:
            self.stream = open_log(self.log)
        return self.stream

    def _start_position(self, stream: BinaryIO) -> FilePosition:
        if self.confirmed is not None:
            size = fstat(stream.fileno()).st_size
            if self.confirmed.offset <= size and file_position(stream, self.confirmed.offset) == self.confirmed:
                return self.confirmed
        return file_position(stream, 0)

    def _was_rotated(self, position: FilePosition) -> bool:
        try:
            current = self.log.stat()
        except FileNotFoundError:
            return False
        return (current.st_dev, current.st_ino) != (position.device, position.inode)

    def sync_once(self, send: Callable[[list[ConnectionMetadata]], tuple[int, int]]) -> tuple[int, int]:
        stream = self._open_if_needed()
        start = self._start_position(stream)
        offset = start.offset
        batch = []
        at_end = False
        while len(batch) < BATCH_SIZE:
            line = stream.readline(MAX_LINE_BYTES + 1)
            if len(line) > MAX_LINE_BYTES:
                raise ValueError(f"Registro na posição {offset} excedeu 64 KiB.")
            if not line:
                at_end = True
                break
            if not line.endswith(b"\n") and not self._was_rotated(start):
                break
            if line.strip():
                try:
                    batch.append(metadata_from_line(line))
                except (ValueError, TypeError, KeyError, OverflowError, OSError) as exc:
                    raise ValueError(f"Registro inválido na posição {offset} do conn.log.") from exc
            offset = stream.tell()

        position = file_position(stream, offset)
        result = send(batch) if batch else (0, 0)
        if position != self.confirmed and (batch or offset != start.offset or self.confirmed is not None):
            save_position(self.checkpoint, position)
            self.confirmed = position
        if at_end and self._was_rotated(position):
            stream.close()
            self.stream = None
            self.confirmed = None
        return result
