from pydantic import BaseModel, field_validator
from typing import Optional
from Helpers.IPconvert import IPInterface

class PacketInformation(BaseModel):
    src_ip: str
    dest_ip: str
    tot_len: int
    ttl: int
    protocol: str
    data_length: Optional[int] = 0 
    data: str
    @field_validator('src_ip','dest_ip', mode="before")
    def convert_ip_to_string(cls, v):
        return IPInterface.opposite_ip(IPInterface.convert_ip_str(v))
        
    @field_validator('data')
    def convert_data_type(clv, v):
        return str(v)