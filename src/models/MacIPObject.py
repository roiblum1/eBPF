from pydantic import BaseModel, field_validator
from typing import List

from src.helpers.IPconvert import IPInterface

class MacIpKey(BaseModel):
    mac: str

    @field_validator('mac', mode="before")
    def format_mac_address(cls, v):
        if isinstance(v, list):
            return ':'.join(f'{byte:02x}' for byte in v)
        return v

class MacIpValue(BaseModel):
    ips: List[str]

    @field_validator('ips', mode="before")
    def convert_ips_to_strings(cls, v):
        if isinstance(v, list):
            return [IPInterface.convert_ip_str(ip) for ip in v if ip != 0]
        return v

class MacIpMapEntry(BaseModel):
    key: MacIpKey
    value: MacIpValue
