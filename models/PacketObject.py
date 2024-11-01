from pydantic import BaseModel, field_validator
from typing import Optional
from ..bpf import bytes_to_ip

class PacketInformation(BaseModel):
    src_ip: str
    dst_ip: str
    tot_len: int
    ttl: int
    protocol: str
    data_length: Optional[int] = 0 
    data: str
    @field_validator(['src_ip','dst_ip'])
    def convert_ip_to_string(cls, v):
        return bytes_to_ip(v)
