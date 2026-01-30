"""Idiomatic Python wrappers for the Sia SDK.

This module provides convenience classes and functions that make the SDK
feel native to Python developers, wrapping the low-level Reader/Writer
traits with standard file-like object support.
"""

from io import BytesIO
from typing import BinaryIO, Optional, Union

from .sia_indexd.indexd_ffi import (
    DownloadOptions,
    PinnedObject,
    Reader,
    Sdk,
    UploadOptions,
    Writer,
)


class BytesReader(Reader):
    """Adapts any file-like object to the Reader trait.

    This allows you to upload data from any source that supports the
    standard Python binary read interface (files, BytesIO, etc.).

    Example:
        # From bytes
        reader = BytesReader(BytesIO(b"hello"))

        # From file
        with open("data.bin", "rb") as f:
            reader = BytesReader(f)
    """

    def __init__(self, stream: BinaryIO, chunk_size: int = 65536):
        """Create a BytesReader from a file-like object.

        Args:
            stream: Any object with a read(n) method returning bytes.
            chunk_size: Size of chunks to read (default 64KiB).
        """
        self._stream = stream
        self._chunk_size = chunk_size

    async def read(self) -> bytes:
        """Read the next chunk of data."""
        return self._stream.read(self._chunk_size)


class BytesWriter(Writer):
    """Adapts any file-like object to the Writer trait.

    This allows you to download data to any destination that supports
    the standard Python binary write interface (files, BytesIO, etc.).

    Example:
        # To BytesIO
        buf = BytesIO()
        writer = BytesWriter(buf)

        # To file
        with open("output.bin", "wb") as f:
            writer = BytesWriter(f)
    """

    def __init__(self, stream: BinaryIO):
        """Create a BytesWriter from a file-like object.

        Args:
            stream: Any object with a write(data) method.
        """
        self._stream = stream

    async def write(self, data: bytes) -> None:
        """Write a chunk of data."""
        if len(data) > 0:
            self._stream.write(data)


async def upload_bytes(
    sdk: Sdk,
    data: bytes,
    options: Optional[UploadOptions] = None,
) -> PinnedObject:
    """Upload bytes directly to the Sia network.

    Args:
        sdk: The SDK instance.
        data: The bytes to upload.
        options: Optional upload options.

    Returns:
        The pinned object representing the uploaded data.

    Example:
        obj = await upload_bytes(sdk, b"hello, world!")
    """
    return await sdk.upload(BytesReader(BytesIO(data)), options or UploadOptions())


async def download_bytes(
    sdk: Sdk,
    obj: PinnedObject,
    options: Optional[DownloadOptions] = None,
) -> bytes:
    """Download an object and return its contents as bytes.

    Args:
        sdk: The SDK instance.
        obj: The pinned object to download.
        options: Optional download options.

    Returns:
        The downloaded data as bytes.

    Example:
        data = await download_bytes(sdk, obj)
    """
    buf = BytesIO()
    await sdk.download(BytesWriter(buf), obj, options or DownloadOptions())
    return buf.getvalue()
