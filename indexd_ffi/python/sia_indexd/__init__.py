# Re-export all public API from the native UniFFI module
from sia_indexd.sia_indexd.indexd_ffi import (
    # Functions
    generate_recovery_phrase,
    validate_recovery_phrase,
    set_logger,
    encoded_size,
    uniffi_set_event_loop,
    # Classes/Objects
    Sdk,
    AppKey,
    EncryptionKey,
    PinnedObject,
    PackedUpload,
    # Records
    Account,
    App,
    AppMeta,
    Host,
    NetAddress,
    ObjectEvent,
    ObjectsCursor,
    PinnedSector,
    PinnedSlab,
    SealedObject,
    Slab,
    UploadOptions,
    DownloadOptions,
    # Enums
    AddressProtocol,
    # Errors
    Error,
    ConnectError,
    UploadError,
    DownloadError,
    AppKeyError,
    SeedError,
    BuilderError,
    EncryptionKeyParseError,
    ObjectError,
    IoError,
    # Base classes for implementing custom traits
    Logger,
    Reader,
    Writer,
    UploadProgressCallback,
    # Protocols (typing interfaces)
    LoggerProtocol,
    ReaderProtocol,
    WriterProtocol,
    UploadProgressCallbackProtocol,
)

# Aliases for common naming conventions
SDK = Sdk
IOError = IoError

# Idiomatic Python wrappers for common operations
from sia_indexd.wrappers import (
    Builder,
    BytesReader,
    BytesWriter,
    upload_bytes,
    download_bytes,
)

__all__ = [
    # Functions
    "generate_recovery_phrase",
    "validate_recovery_phrase",
    "set_logger",
    "encoded_size",
    "uniffi_set_event_loop",
    # Classes/Objects
    "SDK",  # alias
    "Builder",
    "AppKey",
    "EncryptionKey",
    "PinnedObject",
    "PackedUpload",
    # Records
    "Account",
    "App",
    "AppMeta",
    "Host",
    "NetAddress",
    "ObjectEvent",
    "ObjectsCursor",
    "PinnedSector",
    "PinnedSlab",
    "SealedObject",
    "Slab",
    "UploadOptions",
    "DownloadOptions",
    # Enums
    "AddressProtocol",
    # Errors
    "Error",
    "ConnectError",
    "UploadError",
    "DownloadError",
    "AppKeyError",
    "SeedError",
    "BuilderError",
    "EncryptionKeyParseError",
    "ObjectError",
    "IOError",  # alias
    # Base classes for implementing custom traits
    "Logger",
    "Reader",
    "Writer",
    "UploadProgressCallback",
    # Protocols (typing interfaces)
    "LoggerProtocol",
    "ReaderProtocol",
    "WriterProtocol",
    "UploadProgressCallbackProtocol",
    # Idiomatic Python wrappers
    "BytesReader",
    "BytesWriter",
    "upload_bytes",
    "download_bytes",
]
