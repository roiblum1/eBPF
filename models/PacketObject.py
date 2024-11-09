from pydantic import BaseModel, field_validator
from typing import Optional
from Helpers.IPconvert import IPInterface

class PacketInformation(BaseModel):
    src_ip: str
    dst_ip: str  
    src_port: Optional[int] = 0
    dst_port: Optional[int] = 0
    tot_len: int
    ttl: int
    protocol: str

    @field_validator('src_ip', 'dst_ip', mode="before")
    def convert_ip_to_string(cls, v):
        return IPInterface.opposite_ip(IPInterface.convert_ip_str(v))
