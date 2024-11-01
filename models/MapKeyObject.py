from pydantic import BaseModel, field_validator
from typing import Optional
from ..bpf import bytes_to_ip

class PacketMapKey(BaseModel):
    src_ip: str
    dst_ip: str
    @field_validator(['src_ip','dst_ip'])
    def convert_ip_to_string(cls, v):
        return bytes_to_ip(v)