from __future__ import annotations

from pathlib import Path
import importlib
import sys


def load_pricing_proto():
    proto_dir = Path(__file__).resolve().parent / "proto"
    generated_dir = proto_dir / "_generated"
    generated_dir.mkdir(exist_ok=True)

    proto_file = proto_dir / "pricing.proto"
    pb2_file = generated_dir / "pricing_pb2.py"
    grpc_file = generated_dir / "pricing_pb2_grpc.py"

    if not pb2_file.exists() or not grpc_file.exists() or pb2_file.stat().st_mtime < proto_file.stat().st_mtime:
        from grpc_tools import protoc

        result = protoc.main(
            [
                "grpc_tools.protoc",
                f"-I{proto_dir}",
                f"--python_out={generated_dir}",
                f"--grpc_python_out={generated_dir}",
                str(proto_file),
            ]
        )
        if result != 0:
            raise RuntimeError("failed to generate pricing gRPC bindings")

    if str(generated_dir) not in sys.path:
        sys.path.insert(0, str(generated_dir))

    pricing_pb2 = importlib.import_module("pricing_pb2")
    pricing_pb2_grpc = importlib.import_module("pricing_pb2_grpc")
    return pricing_pb2, pricing_pb2_grpc
