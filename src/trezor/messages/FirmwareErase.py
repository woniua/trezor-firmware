# Automatically generated by pb2py
# fmt: off
import protobuf as p


class FirmwareErase(p.MessageType):
    MESSAGE_WIRE_TYPE = 6

    def __init__(
        self,
        length: int = None,
    ) -> None:
        self.length = length

    @classmethod
    def get_fields(cls):
        return {
            1: ('length', p.UVarintType, 0),
        }