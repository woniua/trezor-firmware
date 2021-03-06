# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class MoneroTransferDetails(p.MessageType):

    def __init__(
        self,
        *,
        additional_tx_pub_keys: List[bytes] = None,
        out_key: bytes = None,
        tx_pub_key: bytes = None,
        internal_output_index: int = None,
        sub_addr_major: int = None,
        sub_addr_minor: int = None,
    ) -> None:
        self.additional_tx_pub_keys = additional_tx_pub_keys if additional_tx_pub_keys is not None else []
        self.out_key = out_key
        self.tx_pub_key = tx_pub_key
        self.internal_output_index = internal_output_index
        self.sub_addr_major = sub_addr_major
        self.sub_addr_minor = sub_addr_minor

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('out_key', p.BytesType, None),
            2: ('tx_pub_key', p.BytesType, None),
            3: ('additional_tx_pub_keys', p.BytesType, p.FLAG_REPEATED),
            4: ('internal_output_index', p.UVarintType, None),
            5: ('sub_addr_major', p.UVarintType, None),
            6: ('sub_addr_minor', p.UVarintType, None),
        }
